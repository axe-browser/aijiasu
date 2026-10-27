//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
	"golang.org/x/sys/unix"
)

const nodeReadLockHelperPath = "AIJIASU_PUBLIC_NODE_READ_LOCK_PATH"

func TestNodeReadLockProcessHelper(t *testing.T) {
	path := os.Getenv(nodeReadLockHelperPath)
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal("cannot open public node-state lock fixture")
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal("cannot hold public node-state lock fixture")
	}
	defer unix.Flock(int(file.Fd()), unix.LOCK_UN)
	fmt.Println("locked")
	var signal string
	if _, err := fmt.Fscanln(os.Stdin, &signal); err != nil || signal != "release" {
		t.Fatal("missing public node-state lock release signal")
	}
}

func TestNodeCommandsCancelReadWhileAnotherProcessHoldsWriteLock(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	session := clientFixtureSession()
	if err := authstore.SaveSession(directory, session); err != nil {
		t.Fatal(err)
	}
	if err := nodemgr.SetFavorite(directory, session.Username, session.Nodes[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err := nodemgr.RecordUse(directory, session.Username, session.Nodes[0].ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(session.Username))
	base := filepath.Join(directory, "nodes-"+hex.EncodeToString(hash[:]))
	before, err := os.ReadFile(base + ".json")
	if err != nil {
		t.Fatal(err)
	}
	childContext, cancelChild := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelChild()
	child := exec.CommandContext(childContext, os.Args[0], "-test.run=^TestNodeReadLockProcessHelper$")
	child.Env = append(os.Environ(), nodeReadLockHelperPath+"="+base+".lock")
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	if scanner := bufio.NewScanner(stdout); !scanner.Scan() || scanner.Text() != "locked" {
		t.Fatal("other process did not acquire the node-state write lock")
	}
	for _, command := range []string{"nodes", "favorites", "recent", "probe"} {
		t.Run(command, func(t *testing.T) {
			dependencies := defaultDependencies()
			entered := make(chan struct{})
			dependencies.loadNodeState = func(ctx context.Context, directory, account string) (nodemgr.State, error) {
				close(entered)
				return nodemgr.LoadContext(ctx, directory, account)
			}
			dependencies.probeNodes = func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
				t.Error("command started network probing after its state read was canceled")
				return nil, context.Canceled
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var output, diagnostic bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- run(ctx, []string{command, "--config-dir", directory, "--json"}, nil, &output, &diagnostic, dependencies)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("node command did not reach its state read")
			}
			select {
			case <-done:
				t.Fatal("state read bypassed the other process's write lock")
			case <-time.After(50 * time.Millisecond):
			}
			cancel()
			select {
			case code := <-done:
				if code != exitCancelled || output.Len() != 0 || diagnostic.String() != "操作已取消。\n" {
					t.Fatal("canceled state read reported success or the wrong failure")
				}
			case <-time.After(time.Second):
				cancelChild()
				<-done
				t.Fatal("canceled state read waited for the external write lock")
			}
		})
	}
	if _, err := fmt.Fprintln(stdin, "release"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatal("other process failed to release the node-state write lock")
	}
	after, err := os.ReadFile(base + ".json")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("canceled node-state readers changed persisted data")
	}
}
