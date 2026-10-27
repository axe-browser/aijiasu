package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"aijiasu-native/internal/native/authstore"
	clientruntime "aijiasu-native/internal/native/runtime"
)

func TestLogoutStopsInsideSessionLifecycleTransaction(t *testing.T) {
	for _, scenario := range []string{"success", "not-running", "stop-failure", "delete-failure", "lock-failure", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			directory := privateCLIStateDirectory(t)
			if err := authstore.SaveSession(directory, clientFixtureSession()); err != nil {
				t.Fatal(err)
			}
			dependencies := defaultDependencies()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			locked, stopCalls := false, 0
			dependencies.logoutSession = func(ctx context.Context, path string, stop func() error) error {
				if scenario == "lock-failure" {
					return errors.New(clientFixtureSecret)
				}
				return authstore.LogoutSessionAfterStopContext(ctx, path, func() error {
					locked = true
					defer func() { locked = false }()
					if err := stop(); err != nil {
						return err
					}
					if scenario == "delete-failure" {
						return errors.New(clientFixtureSecret)
					}
					return nil
				})
			}
			dependencies.runtimeCall = func(_ context.Context, path string, request clientruntime.Request) (clientruntime.Status, error) {
				stopCalls++
				if !locked || path != directory || request.Command != "stop" {
					t.Fatal("logout contacted the worker outside its lifecycle transaction")
				}
				switch scenario {
				case "not-running":
					return clientruntime.Status{}, clientruntime.ErrNotRunning
				case "stop-failure":
					return clientruntime.Status{}, errors.New(clientFixtureSecret)
				case "canceled":
					cancel()
					return clientruntime.Status{}, context.Canceled
				default:
					return clientruntime.Status{}, nil
				}
			}
			var stdout, stderr bytes.Buffer
			code := run(ctx, []string{"logout", "--config-dir", directory, "--json"}, nil, &stdout, &stderr, dependencies)
			_, sessionErr := authstore.LoadSession(directory)
			if scenario == "success" || scenario == "not-running" {
				if code != 0 || stopCalls != 1 || !errors.Is(sessionErr, os.ErrNotExist) || !strings.Contains(stdout.String(), `"logged_out":true`) || stderr.Len() != 0 {
					t.Fatal("successful logout did not complete its stop/delete transaction")
				}
			} else {
				wantCode, wantCalls := exitFailure, 1
				if scenario == "canceled" {
					wantCode = exitCancelled
				} else if scenario == "lock-failure" {
					wantCalls = 0
				}
				if code != wantCode || stopCalls != wantCalls || sessionErr != nil || stdout.Len() != 0 || stderr.Len() == 0 {
					t.Fatal("failed logout removed a session or reported success")
				}
				if scenario == "delete-failure" && !strings.Contains(stderr.String(), "代理已停止") {
					t.Fatal("logout did not distinguish failure after stopping the worker")
				}
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}
