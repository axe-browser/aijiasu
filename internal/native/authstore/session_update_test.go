//go:build darwin || linux || windows

package authstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRefreshedSessionRejectsLogoutLoginAndConcurrentRefresh(t *testing.T) {
	for _, change := range []string{"logout", "new-login", "identical-login", "other-refresh"} {
		t.Run(change, func(t *testing.T) {
			directory := privateDirectory(t)
			original := publicSession()
			if err := SaveSession(directory, original); err != nil {
				t.Fatal(err)
			}
			prior, err := LoadSession(directory)
			if err != nil {
				t.Fatal(err)
			}
			version, err := VersionOfSession(directory, prior)
			if err != nil {
				t.Fatal(err)
			}
			replacement := original
			switch change {
			case "logout":
				if err := LogoutSession(directory); err != nil {
					t.Fatal(err)
				}
			case "new-login":
				replacement.Username, replacement.LoginToken = "new-public-account", "new-public-token"
				if err := SaveSession(directory, replacement); err != nil {
					t.Fatal(err)
				}
			case "identical-login":
				// File identity must reject a new publication even with identical JSON.
				if err := SaveSession(directory, replacement); err != nil {
					t.Fatal(err)
				}
			case "other-refresh":
				replacement.LoginToken = "winning-public-refresh-token"
				if err := SaveRefreshedSession(directory, version, replacement); err != nil {
					t.Fatal(err)
				}
			}
			stale := original
			stale.LoginToken = "stale-public-refresh-token"
			if err := SaveRefreshedSession(directory, version, stale); !errors.Is(err, ErrSessionChanged) {
				t.Fatalf("stale refresh error = %v", err)
			}
			stored, err := LoadSession(directory)
			if change == "logout" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refresh recreated logged-out session")
				}
			} else if err != nil || !reflect.DeepEqual(stored, replacement) {
				t.Fatal("stale refresh changed the winning session")
			}
			assertNoTemporaryFiles(t, directory)
		})
	}
}

func TestSessionVersionValidatesSnapshotAndDirectory(t *testing.T) {
	directory := privateDirectory(t)
	prior := publicSession()
	if err := SaveSession(directory, prior); err != nil {
		t.Fatal(err)
	}
	version, err := VersionOfSession(directory, prior)
	if err != nil {
		t.Fatal(err)
	}
	stale := prior
	stale.LoginToken = "wrong-public-token"
	if _, err := VersionOfSession(directory, stale); !errors.Is(err, ErrSessionChanged) {
		t.Fatal("accepted stale caller snapshot")
	}
	other := privateDirectory(t)
	if err := SaveSession(other, prior); err != nil {
		t.Fatal(err)
	}
	if err := SaveRefreshedSession(other, version, stale); !errors.Is(err, ErrSessionChanged) {
		t.Fatal("accepted another directory's version")
	}
	if err := SaveRefreshedSession(directory, SessionVersion{}, stale); !errors.Is(err, ErrSessionChanged) {
		t.Fatal("accepted an empty version")
	}
	if err := SaveRefreshedSession(directory, version, stale); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadSession(directory)
	if err != nil || !reflect.DeepEqual(stored, stale) {
		t.Fatal("unchanged session could not refresh")
	}
}

func TestRefreshRejectsRecreatedConfigurationDirectory(t *testing.T) {
	directory := privateDirectory(t)
	prior := publicSession()
	if err := SaveSession(directory, prior); err != nil {
		t.Fatal(err)
	}
	version, err := VersionOfSession(directory, prior)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	if err := SaveSession(directory, prior); err != nil {
		t.Fatal(err)
	}
	updated := prior
	updated.LoginToken = "stale-directory-public-token"
	if err := SaveRefreshedSession(directory, version, updated); !errors.Is(err, ErrSessionChanged) {
		t.Fatal("refresh accepted recreated configuration directory")
	}
	stored, err := LoadSession(directory)
	if err != nil || !reflect.DeepEqual(stored, prior) {
		t.Fatal("refresh changed recreated directory's session")
	}
}

const sessionProcessDirectory = "AIJIASU_PUBLIC_SESSION_LOCK_TEST_DIRECTORY"

func TestSessionUpdateProcessHelper(t *testing.T) {
	directory := os.Getenv(sessionProcessDirectory)
	if directory == "" {
		return
	}
	prior, err := LoadSession(directory)
	if err != nil {
		t.Fatal(err)
	}
	version, err := VersionOfSession(directory, prior)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("captured")
	var command string
	if _, err := fmt.Fscanln(os.Stdin, &command); err != nil || command != "commit" {
		t.Fatal("missing public test signal")
	}
	prior.LoginToken = "stale-child-refresh-token"
	if err := SaveRefreshedSession(directory, version, prior); !errors.Is(err, ErrSessionChanged) {
		t.Fatalf("child stale refresh = %v", err)
	}
}

func TestSessionRefreshCommitSerializesWithOtherProcessLogout(t *testing.T) {
	directory := privateDirectory(t)
	if err := SaveSession(directory, publicSession()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSessionUpdateProcessHelper$")
	command.Env = append(os.Environ(), sessionProcessDirectory+"="+directory)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "captured" {
		t.Fatal("child did not capture its session version")
	}
	root, err := openPrivateDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := acquireSessionLock(root)
	if err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			releaseSessionLock(lock)
		}
	}()
	// Model logout while holding the very same publication lock.
	if err := root.Remove(sessionFileName); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(stdin, "commit"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
		t.Fatal("refresh commit bypassed the held cross-process session lock")
	case <-time.After(100 * time.Millisecond):
	}
	releaseSessionLock(lock)
	locked = false
	if err := <-done; err != nil {
		t.Fatalf("stale child refresh failed its safety check: %v", err)
	}
	if _, err := LoadSession(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("child recreated logged-out session")
	}
}

func TestSessionLockRejectsUnsafeFilesWithoutChangingSession(t *testing.T) {
	for _, kind := range []string{"public", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			if runtime.GOOS == "windows" && kind == "public" {
				t.Skip("Unix permission bits; Windows DACL rejection is covered separately")
			}
			directory := privateDirectory(t)
			original := publicSession()
			if err := SaveSession(directory, original); err != nil {
				t.Fatal(err)
			}
			lockPath := filepath.Join(directory, sessionLockName)
			if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "public":
				if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), lockPath); err != nil {
					t.Skip("symbolic links unavailable")
				}
			case "directory":
				if err := os.Mkdir(lockPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			updated := original
			updated.LoginToken = "must-not-be-written"
			if err := SaveSession(directory, updated); err == nil || strings.Contains(err.Error(), updated.LoginToken) {
				t.Fatal("unsafe lock was accepted or disclosed data")
			}
			if err := LogoutSession(directory); err == nil {
				t.Fatal("logout bypassed unsafe lock")
			}
			stored, err := LoadSession(directory)
			if err != nil || !reflect.DeepEqual(stored, original) {
				t.Fatal("unsafe lock changed existing session")
			}
		})
	}
}
