//go:build darwin || linux || windows

package authstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionLifecycleEntrancesCancelWhileTheLifecycleLockIsHeld(t *testing.T) {
	for _, kind := range []string{"begin-login", "capture-refresh", "startup-gate", "logout"} {
		for _, interrupt := range []string{"cancel", "deadline"} {
			t.Run(kind+"/"+interrupt, func(t *testing.T) {
				directory := privateDirectory(t)
				prior := publicSession()
				if err := SaveSession(directory, prior); err != nil {
					t.Fatal(err)
				}
				pending, err := BeginLogin(directory)
				if err != nil {
					t.Fatal(err)
				}
				release, err := LockSessionLifecycle(directory)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				ctx, cancel := context.WithCancel(context.Background())
				wantErr := context.Canceled
				if interrupt == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 60*time.Millisecond)
					wantErr = context.DeadlineExceeded
				}
				defer cancel()
				var stopCalled atomic.Bool
				done := make(chan error, 1)
				go func() {
					var err error
					switch kind {
					case "begin-login":
						_, err = BeginLoginContext(ctx, directory)
					case "capture-refresh":
						_, err = VersionOfSessionContext(ctx, directory, prior)
					case "startup-gate":
						var unlock func()
						unlock, err = LockSessionLifecycleContext(ctx, directory)
						if unlock != nil {
							unlock()
						}
					case "logout":
						err = LogoutSessionAfterStopContext(ctx, directory, func() error {
							stopCalled.Store(true)
							return nil
						})
					}
					done <- err
				}()
				completed := false
				var outcome error
				select {
				case outcome = <-done:
					completed = true
					if interrupt != "deadline" || !errors.Is(outcome, context.DeadlineExceeded) {
						t.Fatal("session operation bypassed the held lifecycle lock")
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
						t.Fatal("canceled session operation kept waiting for the held lock")
					}
				}
				if !errors.Is(outcome, wantErr) || stopCalled.Load() {
					t.Fatal("interrupted operation started a stop callback or lost cancellation")
				}
				stored, err := LoadSession(directory)
				if err != nil || !reflect.DeepEqual(stored, prior) {
					t.Fatal("interrupted session operation changed the stored session")
				}
				release()
				if err := SaveLoginSession(directory, pending, prior); err != nil {
					t.Fatal("interrupted operation changed its revision or retained its lock")
				}
				assertNoTemporaryFiles(t, directory)
			})
		}
	}
}

func TestSessionLifecycleEntrancesRejectMissingAndCanceledContextBeforeStorage(t *testing.T) {
	for _, kind := range []string{"begin-login", "capture-refresh", "startup-gate", "logout"} {
		for _, missing := range []bool{false, true} {
			directory := filepath.Join(privateDirectory(t), "must-not-be-created")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if missing {
				ctx = nil
			}
			var err error
			stopCalled := false
			switch kind {
			case "begin-login":
				_, err = BeginLoginContext(ctx, directory)
			case "capture-refresh":
				_, err = VersionOfSessionContext(ctx, directory, publicSession())
			case "startup-gate":
				var unlock func()
				unlock, err = LockSessionLifecycleContext(ctx, directory)
				if unlock != nil {
					unlock()
				}
			case "logout":
				err = LogoutSessionAfterStopContext(ctx, directory, func() error { stopCalled = true; return nil })
			}
			if err == nil || !missing && !errors.Is(err, context.Canceled) || stopCalled {
				t.Fatal("invalid context started a session operation")
			}
			if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected operation created its private directory")
			}
		}
	}
}

func TestLogoutCancellationAfterStoppingKeepsTheSession(t *testing.T) {
	directory := privateDirectory(t)
	prior := publicSession()
	if err := SaveSession(directory, prior); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopCalled := false
	err := LogoutSessionAfterStopContext(ctx, directory, func() error {
		stopCalled = true
		cancel()
		return nil
	})
	if !stopCalled || !errors.Is(err, context.Canceled) {
		t.Fatal("logout ignored cancellation after stopping the worker")
	}
	stored, err := LoadSession(directory)
	if err != nil || !reflect.DeepEqual(stored, prior) {
		t.Fatal("canceled logout removed or changed the retained session")
	}
	if err := LogoutSessionAfterStop(directory, func() error { return nil }); err != nil {
		t.Fatal("canceled logout retained its lifecycle lock")
	}
}
