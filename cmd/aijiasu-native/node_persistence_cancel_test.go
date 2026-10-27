//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
	"golang.org/x/sys/unix"
)

func TestNodeCommandsCancelWhileWaitingToSaveWithoutReportingSuccess(t *testing.T) {
	for _, command := range []string{"probe", "favorite"} {
		t.Run(command, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.Close()
				}
			}()
			_, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			session := clientFixtureSession()
			session.Nodes = []clientapi.Node{{ID: "local-node", Host: "127.0.0.1", TCPPort: port}}
			if err := authstore.SaveSession(directory, session); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte(session.Username))
			base := "nodes-" + hex.EncodeToString(hash[:])
			lock, err := os.OpenFile(filepath.Join(directory, base+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
			entered := make(chan struct{})
			dependencies := defaultDependencies()
			args := []string{"probe", "--config-dir", directory, "--json"}
			if command == "probe" {
				dependencies.saveLatencies = func(ctx context.Context, directory, account string, results []nodemgr.Latency) error {
					close(entered)
					return nodemgr.SaveLatenciesContext(ctx, directory, account, results)
				}
			} else {
				args = []string{"favorite", "add", "--config-dir", directory, "--json", "local-node"}
				dependencies.setFavorite = func(ctx context.Context, directory, account, id string, favorite bool) error {
					close(entered)
					return nodemgr.SetFavoriteContext(ctx, directory, account, id, favorite)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() { done <- run(ctx, args, nil, &stdout, &stderr, dependencies) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("node command did not reach persistence")
			}
			cancel()
			select {
			case code := <-done:
				if code != exitCancelled || stdout.Len() != 0 || stderr.String() != "操作已取消。\n" {
					t.Fatal("canceled node command reported success or the wrong failure")
				}
			case <-time.After(time.Second):
				_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
				<-done
				t.Fatal("canceled node command still waited for the held persistence lock")
			}
			if _, err := os.Stat(filepath.Join(directory, base+".json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("canceled node command created persisted state")
			}
		})
	}
}
