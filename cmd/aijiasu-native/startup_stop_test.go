package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"aijiasu-native/internal/native/nodemgr"
	clientruntime "aijiasu-native/internal/native/runtime"
)

func TestBestStartupStopDoesNotTryAnotherCandidate(t *testing.T) {
	for _, command := range []string{"connect", "switch"} {
		for _, interrupt := range []bool{false, true} {
			name := command + "/remote-stop"
			if interrupt {
				name = command + "/foreground-cancel"
			}
			t.Run(name, func(t *testing.T) {
				dependencies := firstConnectDependencies(t)
				state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
				for index, node := range clientFixtureSession().Nodes {
					state.Entries[node.ID] = nodemgr.Entry{ID: node.ID, Latency: managedFixtureLatency(node, float64(index+1), time.Now())}
				}
				dependencies.loadNodeState = func(context.Context, string, string) (nodemgr.State, error) { return state, nil }
				password := []byte(clientFixtureSecret)
				dependencies.readPassword = func(context.Context) ([]byte, error) { return password, nil }
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				runs := 0
				var runtimePassword []byte
				dependencies.runtimeRun = func(_ context.Context, config clientruntime.Config, _ string, _ func(clientruntime.Status)) error {
					runs++
					runtimePassword = config.Password
					if interrupt {
						cancel()
						return context.Canceled
					}
					// A successful remote stop completes Run before its ready callback.
					return nil
				}
				var stdout, stderr bytes.Buffer
				code := run(ctx, []string{command, "--best", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
				wantCode := 0
				if interrupt {
					wantCode = exitCancelled
				}
				if code != wantCode || runs != 1 || stdout.Len() != 0 {
					t.Fatalf("stopped startup code=%d runs=%d output-bytes=%d", code, runs, stdout.Len())
				}
				for _, buffer := range [][]byte{password, runtimePassword} {
					if !bytes.Equal(buffer, make([]byte, len(buffer))) {
						t.Fatal("stopped startup retained a password buffer")
					}
				}
				assertClientOutputSafe(t, &stdout, &stderr)
			})
		}
	}
}
