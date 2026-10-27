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

func TestRefreshCannotUndoLogoutOrOverwriteNewLogin(t *testing.T) {
	for _, action := range []string{"logout", "new-login"} {
		t.Run(action, func(t *testing.T) {
			directory := privateCLIStateDirectory(t)
			prior := clientFixtureSession()
			if err := authstore.SaveSession(directory, prior); err != nil {
				t.Fatal(err)
			}
			dependencies := defaultDependencies()
			dependencies.loadProfile = func(string) (clientapi.Profile, error) { return clientapi.Profile{}, nil }
			started, release := make(chan struct{}), make(chan struct{})
			dependencies.newSyncClient = func(clientapi.Config) (syncClient, error) {
				return fakeSyncClient(func(ctx context.Context, session clientapi.Session) (clientapi.Session, error) {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
						return clientapi.Session{}, ctx.Err()
					}
					session.LoginToken = "stale-public-response-token"
					session.Nodes = []clientapi.Node{{ID: "stale-response-node"}}
					return session, nil
				}), nil
			}
			dependencies.runtimeCall = func(context.Context, string, clientruntime.Request) (clientruntime.Status, error) {
				return clientruntime.Status{}, clientruntime.ErrNotRunning
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- run(ctx, []string{"refresh", "--config-dir", directory, "--json"}, nil, &stdout, &stderr, dependencies)
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("refresh did not start")
			}
			replacement := prior
			if action == "logout" {
				var logoutOut, logoutErr bytes.Buffer
				if code := run(ctx, []string{"logout", "--config-dir", directory}, nil, &logoutOut, &logoutErr, dependencies); code != 0 {
					t.Fatal("concurrent logout failed")
				}
			} else {
				replacement.Username, replacement.LoginToken = "new-public-account", "new-public-login-token"
				if err := authstore.SaveSession(directory, replacement); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if code := <-done; code != exitFailure || stdout.Len() != 0 || !strings.Contains(stderr.String(), "登录状态已变更") {
				t.Fatal("stale refresh was saved or reported success")
			}
			stored, err := authstore.LoadSession(directory)
			if action == "logout" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refresh undid logout")
				}
			} else if err != nil || !reflect.DeepEqual(stored, replacement) {
				t.Fatal("refresh overwrote new login")
			}
			assertClientOutputSafe(t, &stdout, &stderr, "stale-public-response-token", "stale-response-node", replacement.LoginToken)
		})
	}
}
