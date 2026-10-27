//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"golang.org/x/sys/unix"
)

func TestSessionCommandsCancelBeforeNetworkOrStopWhileWaitingForLifecycleLock(t *testing.T) {
	for _, command := range []string{"login", "refresh", "logout"} {
		t.Run(command, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			prior := clientFixtureSession()
			if err := authstore.SaveSession(directory, prior); err != nil {
				t.Fatal(err)
			}
			lock, err := os.OpenFile(filepath.Join(directory, "session.lock"), os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
			dependencies := defaultDependencies()
			dependencies.loadProfile = func(string) (clientapi.Profile, error) { return clientapi.Profile{}, nil }
			var remoteCalls atomic.Int32
			dependencies.newClient = func(clientapi.Config) (loginClient, error) {
				return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
					remoteCalls.Add(1)
					return prior, nil
				}), nil
			}
			dependencies.newSyncClient = func(clientapi.Config) (syncClient, error) {
				return fakeSyncClient(func(context.Context, clientapi.Session) (clientapi.Session, error) {
					remoteCalls.Add(1)
					return prior, nil
				}), nil
			}
			entered := make(chan struct{})
			dependencies.beginLogin = func(ctx context.Context, directory string) (authstore.LoginVersion, error) {
				close(entered)
				return authstore.BeginLoginContext(ctx, directory)
			}
			dependencies.sessionVersion = func(ctx context.Context, directory string, session clientapi.Session) (authstore.SessionVersion, error) {
				close(entered)
				return authstore.VersionOfSessionContext(ctx, directory, session)
			}
			dependencies.logoutSession = func(ctx context.Context, directory string, stop func() error) error {
				close(entered)
				return authstore.LogoutSessionAfterStopContext(ctx, directory, func() error {
					remoteCalls.Add(1)
					return stop()
				})
			}
			args := []string{command, "--config-dir", directory}
			if command == "login" {
				args = append(args, "-u", prior.Username, "--password-stdin")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- run(ctx, args, strings.NewReader("public-cancel-password\n"), &stdout, &stderr, dependencies)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("session command did not reach its lifecycle lock")
			}
			cancel()
			select {
			case code := <-done:
				if code != exitCancelled || remoteCalls.Load() != 0 || stdout.Len() != 0 || stderr.String() != "操作已取消。\n" {
					t.Fatal("canceled lifecycle operation reached a remote action or reported success")
				}
			case <-time.After(time.Second):
				_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
				<-done
				t.Fatal("canceled lifecycle operation still waited for its lock")
			}
			stored, err := authstore.LoadSession(directory)
			if err != nil || !reflect.DeepEqual(stored, prior) {
				t.Fatal("canceled lifecycle operation changed the session")
			}
		})
	}
}

func TestSessionCommandsCancelWhileWaitingToCommitWithoutReportingSuccess(t *testing.T) {
	for _, command := range []string{"first-login", "login", "refresh"} {
		t.Run(command, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			prior := clientFixtureSession()
			if command != "first-login" {
				if err := authstore.SaveSession(directory, prior); err != nil {
					t.Fatal(err)
				}
			}
			lock, err := os.OpenFile(filepath.Join(directory, "session.lock"), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
			updated := prior
			updated.LoginToken = "public-canceled-session-response"
			response := func() (clientapi.Session, error) {
				if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
					return clientapi.Session{}, err
				}
				return updated, nil
			}
			dependencies := defaultDependencies()
			dependencies.loadProfile = func(string) (clientapi.Profile, error) { return clientapi.Profile{}, nil }
			dependencies.newClient = func(clientapi.Config) (loginClient, error) {
				return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) { return response() }), nil
			}
			dependencies.newSyncClient = func(clientapi.Config) (syncClient, error) {
				return fakeSyncClient(func(context.Context, clientapi.Session) (clientapi.Session, error) { return response() }), nil
			}
			entered := make(chan struct{})
			dependencies.saveLoginSession = func(ctx context.Context, directory string, version authstore.LoginVersion, session clientapi.Session) error {
				close(entered)
				return authstore.SaveLoginSessionContext(ctx, directory, version, session)
			}
			dependencies.saveRefreshedSession = func(ctx context.Context, directory string, version authstore.SessionVersion, session clientapi.Session) error {
				close(entered)
				return authstore.SaveRefreshedSessionContext(ctx, directory, version, session)
			}
			args := []string{"login", "-u", prior.Username, "--config-dir", directory, "--password-stdin"}
			if command == "refresh" {
				args = []string{"refresh", "--config-dir", directory, "--json"}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- run(ctx, args, strings.NewReader("public-cancel-password\n"), &stdout, &stderr, dependencies)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("session command did not reach its commit")
			}
			cancel()
			select {
			case code := <-done:
				if code != exitCancelled || stdout.Len() != 0 || stderr.String() != "操作已取消。\n" {
					t.Fatal("canceled session command reported success or the wrong failure")
				}
			case <-time.After(time.Second):
				_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
				<-done
				t.Fatal("canceled session command still waited for the held lock")
			}
			stored, err := authstore.LoadSession(directory)
			if command == "first-login" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("canceled first login created a session")
				}
			} else if err != nil || !reflect.DeepEqual(stored, prior) {
				t.Fatal("canceled session command changed the prior session")
			}
			assertClientOutputSafe(t, &stdout, &stderr, "public-cancel-password", updated.LoginToken)
		})
	}
}
