//go:build darwin || linux || windows

package authstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCanceledSessionCommitsDoNotWaitForOrPublishAfterTheLock(t *testing.T) {
	for _, kind := range []string{"first-password", "password", "refresh"} {
		for _, interrupt := range []string{"cancel", "deadline"} {
			t.Run(kind+"/"+interrupt, func(t *testing.T) {
				directory := privateDirectory(t)
				prior := publicSession()
				if kind != "first-password" {
					if err := SaveSession(directory, prior); err != nil {
						t.Fatal(err)
					}
				}
				login, err := BeginLogin(directory)
				if err != nil {
					t.Fatal(err)
				}
				var refresh SessionVersion
				if kind == "refresh" {
					refresh, err = VersionOfSession(directory, prior)
					if err != nil {
						t.Fatal(err)
					}
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
				ctx, cancel := context.WithCancel(context.Background())
				wantErr := context.Canceled
				if interrupt == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 60*time.Millisecond)
					wantErr = context.DeadlineExceeded
				}
				defer cancel()
				updated := prior
				updated.LoginToken = "public-interrupted-response-token"
				save := func(operation context.Context) error {
					if kind == "refresh" {
						return SaveRefreshedSessionContext(operation, directory, refresh, updated)
					}
					return SaveLoginSessionContext(operation, directory, login, updated)
				}
				done := make(chan error, 1)
				go func() { done <- save(ctx) }()
				completed := false
				var outcome error
				select {
				case outcome = <-done:
					completed = true
					if interrupt != "deadline" || !errors.Is(outcome, context.DeadlineExceeded) {
						t.Fatal("session commit bypassed the held cross-process lock")
					}
				case <-time.After(20 * time.Millisecond):
				}
				if interrupt == "cancel" {
					cancel()
				}
				if !completed {
					select {
					case outcome = <-done:
					case <-time.After(time.Second):
						t.Fatal("canceled commit kept waiting for the held lock")
					}
				}
				if !errors.Is(outcome, wantErr) || strings.Contains(outcome.Error(), updated.LoginToken) {
					t.Fatal("session cancellation lost its cause or disclosed response data")
				}
				stored, err := LoadSession(directory)
				if kind == "first-password" {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatal("canceled first password response created a session")
					}
				} else if err != nil || !reflect.DeepEqual(stored, prior) {
					t.Fatal("canceled response changed the original session")
				}
				releaseSessionLock(lock)
				locked = false
				if err := save(context.Background()); err != nil {
					t.Fatal("canceled lock waiting invalidated state or leaked the commit lock")
				}
				stored, err = LoadSession(directory)
				if err != nil || !reflect.DeepEqual(stored, updated) {
					t.Fatal("a subsequent active command could not commit normally")
				}
				assertNoTemporaryFiles(t, directory)
			})
		}
	}
}

func TestSessionCommitRejectsCanceledOrMissingContextBeforeStorage(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			directory := filepath.Join(privateDirectory(t), "must-not-be-created")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if missing {
				ctx = nil
			}
			var err error
			if refresh {
				err = SaveRefreshedSessionContext(ctx, directory, SessionVersion{}, publicSession())
			} else {
				err = SaveLoginSessionContext(ctx, directory, LoginVersion{}, publicSession())
			}
			if err == nil || !missing && !errors.Is(err, context.Canceled) {
				t.Fatal("invalid or canceled context reached storage or lost cancellation")
			}
			if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected session commit created its configuration directory")
			}
		}
	}
}

// Interrupt at a filesystem boundary rather than depending on the number of
// cancellation checks or filesystem timing between Write, Sync and Rename.
type cancelAtTemporarySession struct {
	context.Context
	directory string
	prepared  bool
	cancel    context.CancelFunc
	triggered atomic.Bool
}

func (operation *cancelAtTemporarySession) Err() error {
	entries, _ := os.ReadDir(operation.directory)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".session-") {
			continue
		}
		info, err := entry.Info()
		if err == nil && (!operation.prepared || info.Size() > 0) {
			operation.triggered.Store(true)
			operation.cancel()
		}
	}
	return operation.Context.Err()
}

func TestCancellationDuringSessionPreparationNeverPublishesTemporaryData(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		directory := privateDirectory(t)
		prior := publicSession()
		if err := SaveSession(directory, prior); err != nil {
			t.Fatal(err)
		}
		root, err := openPrivateDirectory(directory)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		operation := &cancelAtTemporarySession{Context: ctx, directory: directory, prepared: prepared, cancel: cancel}
		published := false
		err = writeSessionContext(operation, root, []byte("public staged session data"), func(old, new string) error {
			published = true
			return root.Rename(old, new)
		})
		cancel()
		_ = root.Close()
		if !operation.triggered.Load() || published || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled session preparation still invoked publication")
		}
		stored, err := LoadSession(directory)
		if err != nil || !reflect.DeepEqual(stored, prior) {
			t.Fatal("canceled session preparation replaced the saved session")
		}
		assertNoTemporaryFiles(t, directory)
	}
}
