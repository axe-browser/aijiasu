package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
	clientruntime "aijiasu-native/internal/native/runtime"
)

func TestCachedEmptyNodesStayOfflineAfterRealSessionRoundTrip(t *testing.T) {
	for _, scenario := range []string{"empty", "legacy-empty", "legacy-minimal"} {
		t.Run(scenario, func(t *testing.T) {
			directory := privateCLIStateDirectory(t)
			session := clientFixtureSession()
			session.Nodes = nil
			if scenario == "empty" {
				session.Nodes = []clientapi.Node{}
			}
			if scenario == "legacy-empty" {
				session.SyncVersion = map[string]string{"Login": "1", "Servers": "2"}
			}
			if scenario == "legacy-empty" {
				data, err := json.Marshal(session)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "session.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := authstore.SaveSession(directory, session); err != nil {
				t.Fatal(err)
			}
			dependencies := defaultDependencies()
			profileCalls := 0
			dependencies.loadProfile = func(string) (clientapi.Profile, error) {
				profileCalls++
				return clientapi.Profile{}, errors.New("public-offline-fixture")
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"nodes", "--config-dir", directory, "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			if scenario == "legacy-minimal" {
				if code != exitFailure || profileCalls != 1 || stdout.Len() != 0 {
					t.Fatal("unsynchronized old session skipped its required refresh")
				}
			} else if code != 0 || profileCalls != 0 || stdout.String() != "[]\n" || stderr.Len() != 0 {
				t.Fatal("known empty cache tried to refresh instead of listing offline")
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestProbeAndBestUseNewerMeasurementCommittedDuringProbe(t *testing.T) {
	for _, command := range []string{"probe", "best"} {
		t.Run(command, func(t *testing.T) {
			directory := privateCLIStateDirectory(t)
			node := managedFixtureNodes()[0]
			session := clientFixtureSession()
			session.Nodes = []clientapi.Node{node}
			if err := authstore.SaveSession(directory, session); err != nil {
				t.Fatal(err)
			}
			newest := *managedFixtureLatency(node, 3, time.Now())
			stale := newest
			stale.CheckedAt = newest.CheckedAt.Add(-20 * time.Second)
			stale.Milliseconds, stale.Successes, stale.Reachable, stale.Error = 0, 0, false, "TCP connection failed"
			dependencies := defaultDependencies()
			dependencies.probeNodes = func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
				// Another command completes after this command measured its node,
				// but before this command commits its entire batch.
				if err := nodemgr.SaveLatencies(directory, session.Username, []nodemgr.Latency{newest}); err != nil {
					return nil, err
				}
				if err := nodemgr.SetFavorite(directory, session.Username, node.ID, true); err != nil {
					return nil, err
				}
				return []nodemgr.Latency{stale}, nil
			}
			selected := ""
			dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
				if request.Command == "status" {
					return clientruntime.Status{Running: true}, nil
				}
				selected = request.NodeID
				return clientruntime.Status{Running: true, Connected: true, NodeID: request.NodeID}, nil
			}
			args := []string{"probe", "--config-dir", directory, "--json"}
			if command == "best" {
				args = []string{"connect", "--best", "--test", "--config-dir", directory, "--json"}
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			if code != 0 {
				t.Fatalf("command rejected the newer reachable measurement: code %d", code)
			}
			if command == "best" {
				if selected != node.ID {
					t.Fatal("automatic selection used the stale probe snapshot")
				}
			} else {
				var nodes []nodeView
				if json.Unmarshal(stdout.Bytes(), &nodes) != nil || len(nodes) != 1 || nodes[0].Reachable == nil || !*nodes[0].Reachable || nodes[0].LatencyMS == nil || *nodes[0].LatencyMS != newest.Milliseconds || !nodes[0].Favorite {
					t.Fatal("probe output did not reconcile the newest stored measurement")
				}
			}
			state, err := nodemgr.Load(directory, session.Username)
			if err != nil || state.Entries[node.ID].Latency == nil || !state.Entries[node.ID].Latency.CheckedAt.Equal(newest.CheckedAt) {
				t.Fatal("stale probe changed the committed measurement")
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestProbeReloadFailureDoesNotPrintStaleSuccess(t *testing.T) {
	nodes := managedFixtureNodes()[:1]
	dependencies := managedDependencies(t, nodes, nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}})
	loads := 0
	dependencies.loadNodeState = func(context.Context, string, string) (nodemgr.State, error) {
		loads++
		if loads > 1 {
			return nodemgr.State{}, errors.New(clientFixtureSecret)
		}
		return nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}, nil
	}
	dependencies.probeNodes = func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		return []nodemgr.Latency{*managedFixtureLatency(nodes[0], 3, time.Now())}, nil
	}
	dependencies.saveLatencies = func(context.Context, string, string, []nodemgr.Latency) error { return nil }
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"probe", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != exitFailure || stdout.Len() != 0 || !strings.Contains(stderr.String(), "节点测速或保存结果失败") {
		t.Fatal("reload failure printed a stale successful result")
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}
