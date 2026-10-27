package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	clientruntime "aijiasu-native/internal/native/runtime"
)

func TestPasswordLoginCannotUndoLogoutOrOverwriteSavedLogin(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, phase := range []string{"password", "service"} {
			for _, action := range []string{"logout", "new-login"} {
				name := phase + "/" + action
				if existing {
					name += "/existing-session"
				} else {
					name += "/first-login"
				}
				t.Run(name, func(t *testing.T) {
					directory := privateCLIStateDirectory(t)
					prior := clientFixtureSession()
					if existing {
						if err := authstore.SaveSession(directory, prior); err != nil {
							t.Fatal(err)
						}
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					started, release := make(chan struct{}), make(chan struct{})
					wait := func() error {
						close(started)
						select {
						case <-release:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					dependencies := defaultDependencies()
					dependencies.loadProfile = func(string) (clientapi.Profile, error) { return clientapi.Profile{}, nil }
					dependencies.readPassword = func(context.Context) ([]byte, error) {
						if phase == "password" {
							if err := wait(); err != nil {
								return nil, err
							}
						}
						return []byte("public-lifecycle-password"), nil
					}
					dependencies.newClient = func(clientapi.Config) (loginClient, error) {
						return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
							if phase == "service" {
								if err := wait(); err != nil {
									return clientapi.Session{}, err
								}
							}
							return prior, nil
						}), nil
					}
					dependencies.runtimeCall = func(context.Context, string, clientruntime.Request) (clientruntime.Status, error) {
						return clientruntime.Status{}, clientruntime.ErrNotRunning
					}
					var stdout, stderr bytes.Buffer
					done := make(chan int, 1)
					go func() {
						done <- run(ctx, []string{"login", "-u", prior.Username, "--config-dir", directory}, nil, &stdout, &stderr, dependencies)
					}()
					select {
					case <-started:
					case <-ctx.Done():
						t.Fatal("password login did not enter the controlled phase")
					}
					replacement := prior
					if action == "logout" {
						var logoutOut, logoutErr bytes.Buffer
						if code := run(ctx, []string{"logout", "--config-dir", directory}, nil, &logoutOut, &logoutErr, dependencies); code != 0 {
							t.Fatal("concurrent logout failed")
						}
					} else {
						replacement.Username, replacement.LoginToken = "winning-public-account", "winning-public-token"
						if err := authstore.SaveSession(directory, replacement); err != nil {
							t.Fatal(err)
						}
					}
					close(release)
					if code := <-done; code != exitFailure || stdout.Len() != 0 || !strings.Contains(stderr.String(), "登录状态已变更") {
						t.Fatal("late password login saved state or reported success")
					}
					stored, err := authstore.LoadSession(directory)
					if action == "logout" {
						if !errors.Is(err, os.ErrNotExist) {
							t.Fatal("late password login recreated the logged-out session")
						}
					} else if err != nil || !reflect.DeepEqual(stored, replacement) {
						t.Fatal("late password login overwrote the committed login")
					}
					assertClientOutputSafe(t, &stdout, &stderr, "public-lifecycle-password", prior.LoginToken, replacement.LoginToken)
				})
			}
		}
	}
}

func TestLoginVersionFailurePrecedesPasswordAndAuthentication(t *testing.T) {
	dependencies := testDependencies()
	dependencies.beginLogin = func(context.Context, string) (authstore.LoginVersion, error) {
		return authstore.LoginVersion{}, errors.New(clientFixtureSecret)
	}
	dependencies.readPassword = func(context.Context) ([]byte, error) {
		t.Fatal("unavailable session version still requested a password")
		return nil, nil
	}
	dependencies.newClient = func(clientapi.Config) (loginClient, error) {
		return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
			t.Fatal("unavailable session version still authenticated")
			return clientapi.Session{}, nil
		}), nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"login", "-u", "public-account"}, nil, &stdout, &stderr, dependencies); code != exitFailure || stdout.Len() != 0 {
		t.Fatal("session version failure reported a successful login")
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}
