//go:build darwin || linux

package runtime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/fvproxy"
)

func TestControlPathFailurePreservesSessionAndRunningWorker(t *testing.T) {
	config := testConfig(t)
	ready, cancel, done := startRuntime(t, config, testDeps(func(fvproxy.Config) (proxyEngine, error) { return &fakeEngine{}, nil }))
	defer cancel()
	parent, err := os.MkdirTemp("/tmp", "ajs-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	alias := filepath.Join(parent, strings.Repeat("a", maxSocketPathBytes))
	if err := os.Symlink(filepath.Dir(config.Directory), alias); err != nil {
		t.Fatal(err)
	}
	aliasedDirectory := filepath.Join(alias, filepath.Base(config.Directory))
	if _, err := authstore.LoadSession(aliasedDirectory); err != nil {
		t.Fatal("long parent alias does not point to the original private session")
	}
	ctx, cancelControl := context.WithTimeout(context.Background(), time.Second)
	defer cancelControl()
	_, err = Call(ctx, aliasedDirectory, Request{Command: "stop"})
	if err == nil || errors.Is(err, ErrNotRunning) || strings.Contains(err.Error(), aliasedDirectory) {
		t.Fatal("invalid control path was treated as a stopped worker or disclosed its path")
	}
	if err := authstore.LogoutSessionAfterStop(aliasedDirectory, func() error {
		_, err := Call(ctx, aliasedDirectory, Request{Command: "stop"})
		// Match the CLI's rule for a worker that is genuinely not running.
		if errors.Is(err, ErrNotRunning) {
			return nil
		}
		return err
	}); err == nil {
		t.Fatal("logout reported success after control failed")
	}
	stored, err := authstore.LoadSession(config.Directory)
	if err != nil || !reflect.DeepEqual(stored, config.Session) {
		t.Fatal("failed worker control removed or changed the session")
	}
	status, err := Call(ctx, config.Directory, Request{Command: "status"})
	if err != nil || !status.Running || !status.Connected || status.ListenAddress != ready.ListenAddress {
		t.Fatal("failed alias control disturbed the original worker")
	}
	if _, err := Call(ctx, config.Directory, Request{Command: "stop"}); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCallRecognizesMissingAndStaleWorkers(t *testing.T) {
	for _, kind := range []string{"missing-directory", "missing-socket", "stale-socket"} {
		t.Run(kind, func(t *testing.T) {
			directory, err := os.MkdirTemp("/tmp", "ajs-rpc-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(directory)
			if kind == "missing-directory" {
				directory = filepath.Join(directory, "missing")
			} else if kind == "stale-socket" {
				path := filepath.Join(directory, socketName)
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				listener.SetUnlinkOnClose(false)
				if err := os.Chmod(path, 0o600); err != nil {
					_ = listener.Close()
					t.Fatal(err)
				}
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
				if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
					t.Fatal("stale socket fixture was not retained")
				}
			}
			if _, err := Call(context.Background(), directory, Request{Command: "status"}); !errors.Is(err, ErrNotRunning) {
				t.Fatalf("missing or stale worker was not recognized: %v", err)
			}
		})
	}
}

func TestRuntimeDialFailuresKeepControlErrorsDistinct(t *testing.T) {
	const privatePath = "public-fixture-control-path-do-not-display"
	for _, test := range []struct {
		name       string
		cause      error
		notRunning bool
	}{
		{"missing", syscall.ENOENT, true},
		{"refused", syscall.ECONNREFUSED, true},
		{"permission", syscall.EACCES, false},
		{"operation", syscall.EPERM, false},
		{"invalid-address", syscall.EINVAL, false},
		{"process-file-limit", syscall.EMFILE, false},
		{"system-file-limit", syscall.ENFILE, false},
		{"buffer-limit", syscall.ENOBUFS, false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := &net.OpError{Op: "dial", Net: "unix", Addr: &net.UnixAddr{Net: "unix", Name: privatePath}, Err: test.cause}
			err := runtimeDialFailure(context.Background(), cause)
			if err == nil || errors.Is(err, ErrNotRunning) != test.notRunning || strings.Contains(err.Error(), privatePath) {
				t.Fatal("control error was misclassified or disclosed its address")
			}
			if !test.notRunning && !errors.Is(err, test.cause) {
				t.Fatal("control failure discarded its diagnostic cause")
			}
		})
	}
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}
		cancel()
		err := runtimeDialFailure(ctx, syscall.ECONNREFUSED)
		if errors.Is(err, ErrNotRunning) || !errors.Is(err, ctx.Err()) {
			t.Fatal("interrupted control request was reported as a stopped worker")
		}
	}
}

func TestRuntimeSocketPathValidationIsSharedByStartupAndControl(t *testing.T) {
	boundary := "/tmp/" + strings.Repeat("a", maxSocketPathBytes-len("/tmp/")-len(socketName)-1)
	if path, err := runtimeDirectoryPath(boundary); err != nil || len(filepath.Join(path, socketName)) != maxSocketPathBytes {
		t.Fatal("valid socket path boundary was rejected")
	}
	for _, directory := range []string{"", boundary + "a"} {
		_, startupErr := openRuntimeDirectory(directory)
		_, controlErr := Call(context.Background(), directory, Request{Command: "status"})
		if startupErr == nil || controlErr == nil || startupErr.Error() != controlErr.Error() || errors.Is(controlErr, ErrNotRunning) {
			t.Fatal("startup and control disagreed about an invalid socket path")
		}
	}
}
