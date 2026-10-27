package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/fvproxy"
)

func TestStartupCancellationDoesNotWaitForTheHeldLifecycleLock(t *testing.T) {
	config := testConfig(t)
	release, err := authstore.LockSessionLifecycle(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var created, ready atomic.Bool
	deps := testDeps(func(fvproxy.Config) (proxyEngine, error) {
		created.Store(true)
		return &fakeEngine{}, nil
	})
	done := make(chan error, 1)
	go func() { done <- run(ctx, config, "a", func(Status) { ready.Store(true) }, deps) }()
	select {
	case <-done:
		t.Fatal("startup bypassed the held lifecycle lock")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || created.Load() || ready.Load() {
			t.Fatal("canceled lock waiting started a network candidate or lost cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled startup kept waiting for the lifecycle lock")
	}
	if _, err := os.Lstat(filepath.Join(config.Directory, socketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled startup registered its control socket")
	}
	assertStartupResourcesClosed(t, config, "")
}
