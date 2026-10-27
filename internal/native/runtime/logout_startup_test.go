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

func TestLogoutOrdersConcurrentStartupBeforeDeletingSession(t *testing.T) {
	for _, initialNode := range []string{"a", ""} {
		name := "connected"
		if initialNode == "" {
			name = "idle"
		}
		t.Run(name, func(t *testing.T) {
			config := testConfig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stopped, releaseLogout := make(chan struct{}), make(chan struct{})
			logoutDone := make(chan error, 1)
			go func() {
				logoutDone <- authstore.LogoutSessionAfterStop(config.Directory, func() error {
					if _, err := Call(ctx, config.Directory, Request{Command: "stop"}); !errors.Is(err, ErrNotRunning) {
						return errors.New("logout expected no initial worker")
					}
					close(stopped)
					select {
					case <-releaseLogout:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			select {
			case <-stopped:
			case <-ctx.Done():
				t.Fatal("logout did not reach its locked stop/delete boundary")
			}
			var engines, ready atomic.Int32
			deps := testDeps(func(fvproxy.Config) (proxyEngine, error) {
				engines.Add(1)
				return &fakeEngine{}, nil
			})
			runDone := make(chan error, 1)
			go func() { runDone <- run(ctx, config, initialNode, func(Status) { ready.Add(1) }, deps) }()
			select {
			case <-runDone:
				t.Fatal("startup did not wait for the active logout transaction")
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := os.Lstat(filepath.Join(config.Directory, socketName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("startup registered a worker inside logout's stop/delete boundary")
			}
			close(releaseLogout)
			if err := await(t, logoutDone); err != nil {
				t.Fatalf("logout failed: %v", err)
			}
			if err := await(t, runDone); err == nil || engines.Load() != 0 || ready.Load() != 0 {
				t.Fatal("a stale startup snapshot survived completed logout")
			}
			if _, err := authstore.LoadSession(config.Directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("logout retained the local session")
			}
			assertStartupResourcesClosed(t, config, "")
		})
	}
}

func TestLogoutStopsWorkerRegisteredBeforeAuthenticationCompletes(t *testing.T) {
	for _, phase := range []string{"authentication", "verification"} {
		t.Run(phase, func(t *testing.T) {
			config := testConfig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			entered := make(chan struct{})
			block := func(operation context.Context) error {
				close(entered)
				<-operation.Done()
				return operation.Err()
			}
			engine := &fakeEngine{}
			deps := testDeps(func(fvproxy.Config) (proxyEngine, error) { return engine, nil })
			if phase == "authentication" {
				engine.auth = block
			} else {
				deps.verify = func(operation context.Context, _ proxyEngine, _ string) (string, error) {
					return "", block(operation)
				}
			}
			var ready atomic.Bool
			runDone := make(chan error, 1)
			go func() { runDone <- run(ctx, config, "a", func(Status) { ready.Store(true) }, deps) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("registered worker did not reach its network operation")
			}
			status, err := Call(ctx, config.Directory, Request{Command: "status"})
			if err != nil || !status.Running || status.Connected {
				t.Fatalf("startup was not reachable before its network operation: %v", err)
			}
			control, cancelControl := context.WithTimeout(ctx, time.Second)
			defer cancelControl()
			if err := authstore.LogoutSessionAfterStop(config.Directory, func() error {
				stopped, err := Call(control, config.Directory, Request{Command: "stop"})
				if err == nil && (stopped.Running || stopped.Connected) {
					return errors.New("logout stop returned before cleanup")
				}
				return err
			}); err != nil {
				t.Fatalf("logout did not cancel registered startup: %v", err)
			}
			if err := await(t, runDone); err != nil || ready.Load() || !engine.isClosed() {
				t.Fatalf("logout retained a startup candidate or emitted readiness: %v", err)
			}
			if _, err := authstore.LoadSession(config.Directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("logout retained the local session")
			}
			assertStartupResourcesClosed(t, config, status.ListenAddress)
		})
	}
}
