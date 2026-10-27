//go:build darwin || linux || windows

package nodemgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCanceledNodeMutationsDoNotCreateTheirDirectory(t *testing.T) {
	for _, operation := range []string{"favorite", "latencies"} {
		t.Run(operation, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "not-created")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var err error
			if operation == "favorite" {
				err = SetFavoriteContext(ctx, directory, stateTestAccount, "node", true)
			} else {
				err = SaveLatenciesContext(ctx, directory, stateTestAccount, []Latency{fixtureLatency("node")})
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("already canceled mutation did not preserve cancellation")
			}
			if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("already canceled mutation created a state directory")
			}
		})
	}
	if err := SetFavoriteContext(nil, "", stateTestAccount, "node", true); err == nil {
		t.Fatal("favorite accepted a missing context")
	}
	if err := SaveLatenciesContext(nil, "", stateTestAccount, nil); err == nil {
		t.Fatal("latencies accepted a missing context")
	}
	if _, err := LoadContext(nil, "", stateTestAccount); err == nil {
		t.Fatal("state snapshot accepted a missing context")
	}
}

func TestNodeMutationCancellationInterruptsHeldLockWithoutChangingState(t *testing.T) {
	for _, operation := range []string{"favorite", "latencies"} {
		t.Run(operation, func(t *testing.T) {
			directory := privateStateDirectory(t)
			if err := SetFavorite(directory, stateTestAccount, "kept", true); err != nil {
				t.Fatal(err)
			}
			before, err := Load(directory, stateTestAccount)
			if err != nil {
				t.Fatal(err)
			}
			root, err := openStateDirectory(directory, false)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			_, lockName, _ := accountNames(stateTestAccount)
			lock, err := acquireStateLock(root, lockName, true)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			defer unlockState(lock)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "favorite" {
					done <- SetFavoriteContext(ctx, directory, stateTestAccount, "kept", false)
				} else {
					done <- SaveLatenciesContext(ctx, directory, stateTestAccount, []Latency{fixtureLatency("kept")})
				}
			}()
			select {
			case <-done:
				t.Fatal("mutation bypassed the held state lock")
			case <-time.After(50 * time.Millisecond):
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("held-lock mutation did not return cancellation")
				}
			case <-time.After(time.Second):
				_ = unlockState(lock)
				<-done
				t.Fatal("mutation waited for lock release after cancellation")
			}
			_ = unlockState(lock)
			after, err := Load(directory, stateTestAccount)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("canceled mutation changed the prior state")
			}
		})
	}
}

func TestCancellationDuringNodeStatePreparationDoesNotPublish(t *testing.T) {
	directory := privateStateDirectory(t)
	if err := SetFavorite(directory, stateTestAccount, "kept", true); err != nil {
		t.Fatal(err)
	}
	before, err := Load(directory, stateTestAccount)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = updateStateContext(ctx, directory, stateTestAccount, func(state *State) map[string]bool {
		delete(state.Entries, "kept")
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation before publication was ignored")
	}
	after, err := Load(directory, stateTestAccount)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("canceled preparation published a new state")
	}
}
