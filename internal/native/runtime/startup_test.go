package runtime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/fvproxy"
)

func assertStartupResourcesClosed(t *testing.T, config Config, address string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(config.Directory, socketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup termination retained the control socket")
	}
	if address != "" {
		if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Fatal("startup termination retained the proxy listener")
		}
	}
	for _, value := range config.Password {
		if value != 0 {
			t.Fatal("startup termination retained the caller's password")
		}
	}
	directory, err := openRuntimeDirectory(config.Directory)
	if err != nil {
		t.Fatalf("startup termination retained the singleton lock: %v", err)
	}
	directory.close()
}

func TestStartupStatusAndStopCancelInitialNetworkOperation(t *testing.T) {
	for _, phase := range []string{"authentication", "verification"} {
		t.Run(phase, func(t *testing.T) {
			config := testConfig(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			candidate := &fakeEngine{}
			block := func(operation context.Context) error {
				close(entered)
				<-operation.Done()
				return operation.Err()
			}
			deps := testDeps(func(fvproxy.Config) (proxyEngine, error) { return candidate, nil })
			if phase == "authentication" {
				candidate.auth = block
			} else {
				deps.verify = func(operation context.Context, _ proxyEngine, _ string) (string, error) { return "", block(operation) }
			}
			var ready atomic.Bool
			done := make(chan error, 1)
			go func() { done <- run(ctx, config, "a", func(Status) { ready.Store(true) }, deps) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("initial network operation did not start")
			}
			control, cancelControl := context.WithTimeout(context.Background(), time.Second)
			defer cancelControl()
			status, err := Call(control, config.Directory, Request{Command: "status"})
			if err != nil || !status.Running || status.Connected || status.ListenAddress == "" || ready.Load() {
				t.Fatalf("startup status was unavailable or prematurely connected: %v", err)
			}
			stopped, err := Call(control, config.Directory, Request{Command: "stop"})
			if err != nil || stopped.Running || stopped.Connected {
				t.Fatalf("stop did not interrupt startup: %v", err)
			}
			if ready.Load() || !candidate.isClosed() {
				t.Fatal("stopped startup emitted readiness or retained its candidate")
			}
			if ctx.Err() != nil {
				t.Fatal("RPC stop unexpectedly canceled the caller's context")
			}
			assertStartupResourcesClosed(t, config, status.ListenAddress)
			if err := await(t, done); err != nil {
				t.Fatalf("explicit startup stop must end the foreground command without candidate retry: %v", err)
			}
		})
	}
}

func TestStartupReservesOperationBeforeQueuedSwitch(t *testing.T) {
	config := testConfig(t)
	entered, release, secondCreated := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps := testDeps(func(cfg fvproxy.Config) (proxyEngine, error) {
		if strings.HasPrefix(cfg.Address, "b.") {
			close(secondCreated)
			return &fakeEngine{}, nil
		}
		return &fakeEngine{auth: func(operation context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-operation.Done():
				return operation.Err()
			}
		}}, nil
	})
	ready := make(chan Status, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, config, "a", func(status Status) { ready <- status }, deps) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial connection did not acquire its operation")
	}
	type callResult struct {
		status Status
		err    error
	}
	switched := make(chan callResult, 1)
	go func() {
		state, err := Call(ctx, config.Directory, Request{Command: "switch", NodeID: "b"})
		switched <- callResult{state, err}
	}()
	select {
	case <-secondCreated:
		t.Fatal("queued switch ran before the initial connection finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case result := <-switched:
		if result.err != nil || !result.status.Connected || result.status.NodeID != "b" {
			t.Fatalf("queued switch did not follow startup: %v", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued switch remained blocked after startup")
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("successful startup did not emit readiness")
	}
	status, err := Call(ctx, config.Directory, Request{Command: "status"})
	if err != nil || status.NodeID != "b" || !status.Connected {
		t.Fatal("late startup overwrote the queued switch")
	}
	if _, err := Call(ctx, config.Directory, Request{Command: "stop"}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestStopConcurrentWithStartupCompletionReturnsNormally(t *testing.T) {
	const attempts = 12
	for attempt := 0; attempt < attempts; attempt++ {
		config := testConfig(t)
		entered, release := make(chan struct{}), make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		deps := testDeps(func(fvproxy.Config) (proxyEngine, error) {
			return &fakeEngine{auth: func(operation context.Context) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-operation.Done():
					return operation.Err()
				}
			}}, nil
		})
		var stopped, lateReady atomic.Bool
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, config, "a", func(Status) {
				if stopped.Load() {
					lateReady.Store(true)
				}
			}, deps)
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("initial connection did not start")
		}
		control, cancelControl := context.WithTimeout(context.Background(), time.Second)
		stopDone := make(chan error, 1)
		go func() {
			_, err := Call(control, config.Directory, Request{Command: "stop"})
			stopped.Store(true)
			stopDone <- err
		}()
		close(release)
		stopErr, runErr := await(t, stopDone), await(t, done)
		cancelControl()
		cancel()
		if stopErr != nil || runErr != nil || lateReady.Load() {
			t.Fatalf("stop/startup race returned an error or late readiness: stop=%v, run=%v", stopErr, runErr)
		}
		assertStartupResourcesClosed(t, config, "")
	}
}

func TestInitialFailureCleansRPCAndAllowsRestart(t *testing.T) {
	for _, phase := range []string{"authentication", "verification"} {
		t.Run(phase, func(t *testing.T) {
			config := testConfig(t)
			candidate := &fakeEngine{}
			deps := testDeps(func(fvproxy.Config) (proxyEngine, error) { return candidate, nil })
			failure := errors.New("constructed initial network failure")
			if phase == "authentication" {
				candidate.auth = func(context.Context) error { return failure }
			} else {
				deps.verify = func(context.Context, proxyEngine, string) (string, error) { return "", failure }
			}
			var ready bool
			if err := run(context.Background(), config, "a", func(Status) { ready = true }, deps); err == nil || ready || !candidate.isClosed() {
				t.Fatal("initial failure was reported as a successful startup")
			}
			assertStartupResourcesClosed(t, config, "")
			config.Password = []byte(testPassword)
			status, _, done := startRuntime(t, config, testDeps(func(fvproxy.Config) (proxyEngine, error) { return &fakeEngine{}, nil }))
			if !status.Connected {
				t.Fatal("cleaned startup could not restart")
			}
			if _, err := Call(context.Background(), config.Directory, Request{Command: "stop"}); err != nil {
				t.Fatal(err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
