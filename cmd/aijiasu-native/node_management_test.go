package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
	clientruntime "aijiasu-native/internal/native/runtime"
)

func managedFixtureNodes() []clientapi.Node {
	return []clientapi.Node{
		{ID: "n1", Title: "Alpha 浙江杭州", Host: "one.example.test", TCPPort: 443},
		{ID: "n2", Title: "Beta 浙江宁波", Host: "two.example.test", TCPPort: 443},
		{ID: "n3", Title: "Gamma 江苏南京", Host: "three.example.test", TCPPort: 443},
	}
}

func managedFixtureLatency(node clientapi.Node, milliseconds float64, checkedAt time.Time) *nodemgr.Latency {
	return &nodemgr.Latency{
		ID: node.ID, Host: node.Host, Port: node.TCPPort, Milliseconds: milliseconds,
		CheckedAt: checkedAt, Attempts: 2, Successes: 2, Reachable: true,
	}
}

func managedDependencies(t *testing.T, nodes []clientapi.Node, state nodemgr.State) cliDependencies {
	t.Helper()
	dependencies := clientCommandDependencies(t)
	dependencies.loadSession = func(string) (clientapi.Session, error) {
		session := clientFixtureSession()
		session.Nodes = nodes
		return session, nil
	}
	dependencies.loadNodeState = func(_ context.Context, directory, account string) (nodemgr.State, error) {
		if directory != filepath.Join("private", "test-config") || account != "public-test-account" {
			t.Fatal("node state was not scoped to the cached account and private directory")
		}
		return state, nil
	}
	dependencies.setFavorite = func(context.Context, string, string, string, bool) error {
		t.Fatal("command changed a favorite unexpectedly")
		return nil
	}
	dependencies.saveLatencies = func(context.Context, string, string, []nodemgr.Latency) error {
		t.Fatal("command saved measurements unexpectedly")
		return nil
	}
	dependencies.probeNodes = func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		t.Fatal("command probed nodes unexpectedly")
		return nil, nil
	}
	return dependencies
}

func TestFavoriteMutationsUseExactIDAndAccountWithoutSecrets(t *testing.T) {
	for _, operation := range []string{"add", "remove"} {
		t.Run(operation, func(t *testing.T) {
			nodes := managedFixtureNodes()
			nodes[1].Title = "name also contains n1"
			dependencies := managedDependencies(t, nodes, nodemgr.State{})
			setCalls := 0
			dependencies.setFavorite = func(_ context.Context, directory, account, id string, favorite bool) error {
				setCalls++
				if directory != filepath.Join("private", "test-config") || account != "public-test-account" || id != "n1" || favorite != (operation == "add") {
					t.Fatalf("incorrect favorite mutation: account %q id %q favorite %v", account, id, favorite)
				}
				return nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"favorite", operation, "--json", "n1"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			var result struct {
				ID       string `json:"id"`
				Favorite bool   `json:"favorite"`
			}
			if code != 0 || setCalls != 1 || json.Unmarshal(stdout.Bytes(), &result) != nil || result.ID != "n1" || result.Favorite != (operation == "add") || stderr.Len() != 0 {
				t.Fatalf("favorite %s = code %d calls %d output %q / %q", operation, code, setCalls, stdout.String(), stderr.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestFavoriteAddRejectsTitleAndSaveFailureDoesNotClaimSuccess(t *testing.T) {
	for _, stage := range []string{"title", "save"} {
		t.Run(stage, func(t *testing.T) {
			dependencies := managedDependencies(t, managedFixtureNodes(), nodemgr.State{})
			id := "杭州"
			calls := 0
			dependencies.setFavorite = func(context.Context, string, string, string, bool) error {
				calls++
				return errors.New(clientFixtureSecret)
			}
			if stage == "save" {
				id = "n1"
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"favorite", "add", id}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			wantCalls := 0
			if stage == "save" {
				wantCalls = 1
			}
			if code != exitFailure || calls != wantCalls || stdout.Len() != 0 || strings.Contains(stderr.String(), "已收藏") {
				t.Fatalf("favorite failure = code %d calls %d output %q / %q", code, calls, stdout.String(), stderr.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestManagedFavoritesAndRecentFilterAndSort(t *testing.T) {
	now := time.Now()
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{
		"n1": {ID: "n1", Favorite: true, LastUsedAt: now.Add(-time.Hour), UseCount: 2},
		"n2": {ID: "n2", LastUsedAt: now, UseCount: 3},
		"n3": {ID: "n3", Favorite: true},
	}}
	for _, test := range []struct {
		name string
		args []string
		ids  []string
	}{
		{"favorites", []string{"favorites", "--json", "--sort", "id"}, []string{"n1", "n3"}},
		{"favorite-list-alias", []string{"favorite", "list", "--json"}, []string{"n1", "n3"}},
		{"recent-newest-first", []string{"recent", "--json"}, []string{"n2", "n1"}},
		{"intersection", []string{"nodes", "--json", "--favorites", "--recent"}, []string{"n1"}},
		{"recent-limit", []string{"recent", "--json", "--limit", "1"}, []string{"n2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := managedDependencies(t, managedFixtureNodes(), state)
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), test.args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			var views []nodeView
			if code != 0 || json.Unmarshal(stdout.Bytes(), &views) != nil || stderr.Len() != 0 {
				t.Fatalf("managed list = code %d, %q / %q", code, stdout.String(), stderr.String())
			}
			ids := make([]string, 0, len(views))
			for _, view := range views {
				ids = append(ids, view.ID)
				entry := state.Entries[view.ID]
				if view.Favorite != entry.Favorite || view.UseCount != entry.UseCount || (view.LastUsedAt == nil) != entry.LastUsedAt.IsZero() {
					t.Fatal("managed node metadata was lost")
				}
			}
			if !reflect.DeepEqual(ids, test.ids) {
				t.Fatalf("managed IDs = %v, want %v", ids, test.ids)
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestLatencySortDoesNotPreferExpiredChangedOrFailedZero(t *testing.T) {
	now := time.Now()
	nodes := []clientapi.Node{
		{ID: "stale", Host: "stale.example.test", TCPPort: 443},
		{ID: "changed", Host: "changed.example.test", TCPPort: 443},
		{ID: "failed", Host: "failed.example.test", TCPPort: 443},
		{ID: "slow", Host: "slow.example.test", TCPPort: 443},
		{ID: "fast", Host: "fast.example.test", TCPPort: 443},
	}
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
	for index, node := range nodes {
		state.Entries[node.ID] = nodemgr.Entry{ID: node.ID, Latency: managedFixtureLatency(node, float64(index+1), now)}
	}
	state.Entries["stale"].Latency.CheckedAt = now.Add(-latencyCacheLifetime - time.Second)
	state.Entries["changed"].Latency.Host = "old.example.test"
	state.Entries["failed"].Latency.Reachable = false
	state.Entries["failed"].Latency.Successes = 0
	state.Entries["failed"].Latency.Milliseconds = 0
	state.Entries["slow"].Latency.Milliseconds = 20
	state.Entries["fast"].Latency.Milliseconds = 10
	dependencies := managedDependencies(t, nodes, state)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"nodes", "--json", "--sort", "latency"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	var views []nodeView
	if code != 0 || json.Unmarshal(stdout.Bytes(), &views) != nil {
		t.Fatalf("latency sorting = code %d, %q / %q", code, stdout.String(), stderr.String())
	}
	var ids []string
	for _, view := range views {
		ids = append(ids, view.ID)
		switch view.ID {
		case "stale":
			if view.LatencyFresh {
				t.Fatal("expired timing was treated as fresh")
			}
		case "changed":
			if view.LatencyMS != nil || view.Reachable != nil {
				t.Fatal("measurement was reused after node host changed")
			}
		case "failed":
			if view.LatencyMS != nil || view.Reachable == nil || *view.Reachable {
				t.Fatal("failed zero-millisecond timing was shown as reachable")
			}
		}
	}
	if !reflect.DeepEqual(ids, []string{"fast", "slow", "changed", "failed", "stale"}) {
		t.Fatalf("latency order = %v", ids)
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}

func TestBestUsesFreshCacheAndBoundsActiveRuntimeFallback(t *testing.T) {
	for _, successAttempt := range []int{1, 3, 0} {
		t.Run(fmt.Sprintf("success-at-%d", successAttempt), func(t *testing.T) {
			nodes := managedFixtureNodes()
			nodes = append(nodes,
				clientapi.Node{ID: "n4", Host: "four.example.test", TCPPort: 443},
				clientapi.Node{ID: "n5", Host: "five.example.test", TCPPort: 443},
			)
			state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
			for index, node := range nodes {
				state.Entries[node.ID] = nodemgr.Entry{ID: node.ID, Latency: managedFixtureLatency(node, float64(index+1)*10, time.Now())}
			}
			dependencies := managedDependencies(t, nodes, state)
			var tried []string
			statusCalls := 0
			dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
				if request.Command == "status" {
					statusCalls++
					return clientruntime.Status{Running: true, Connected: true, NodeID: "old-node"}, nil
				}
				if request.Command != "connect" {
					t.Fatalf("unexpected active command: %q", request.Command)
				}
				tried = append(tried, request.NodeID)
				if len(tried) == successAttempt {
					return clientruntime.Status{Running: true, Connected: true, NodeID: request.NodeID}, nil
				}
				return clientruntime.Status{}, errors.New(clientFixtureSecret)
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"connect", "--best", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			wantTries, wantCode := 3, exitFailure
			if successAttempt != 0 {
				wantTries, wantCode = successAttempt, 0
			}
			if code != wantCode || statusCalls != 1 || !reflect.DeepEqual(tried, []string{"n1", "n2", "n3"}[:wantTries]) {
				t.Fatalf("best fallback = code %d status calls %d tried %v", code, statusCalls, tried)
			}
			if successAttempt == 0 && stdout.Len() != 0 || successAttempt != 0 && stdout.Len() == 0 {
				t.Fatalf("best success output mismatched RPC result: %q", stdout.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestBestProbesOnlyStaleOrChangedNodesBeforeSelecting(t *testing.T) {
	nodes := managedFixtureNodes()
	now := time.Now()
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{
		"n1": {ID: "n1", Latency: managedFixtureLatency(nodes[0], 10, now)},
		"n2": {ID: "n2", Latency: managedFixtureLatency(nodes[1], 1, now.Add(-time.Hour))},
		"n3": {ID: "n3", Latency: managedFixtureLatency(nodes[2], 1, now)},
	}}
	state.Entries["n3"].Latency.Host = "previous.example.test"
	dependencies := managedDependencies(t, nodes, state)
	var events []string
	dependencies.probeNodes = func(_ context.Context, probed []clientapi.Node, config nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		events = append(events, "probe")
		if !reflect.DeepEqual(probed, nodes[1:]) || config.Attempts != 2 || config.Concurrency != 8 || config.Timeout != 2*time.Second || config.Budget != 30*time.Second {
			t.Fatal("best did not limit probing to stale/changed nodes with bounded defaults")
		}
		return []nodemgr.Latency{
			*managedFixtureLatency(nodes[1], 5, now),
			{ID: "n3", Host: nodes[2].Host, Port: 443, Attempts: 2, CheckedAt: now, Error: "TCP connection failed"},
		}, nil
	}
	dependencies.saveLatencies = func(_ context.Context, directory, account string, results []nodemgr.Latency) error {
		events = append(events, "save")
		if directory != filepath.Join("private", "test-config") || account != "public-test-account" || len(results) != 2 {
			t.Fatal("measurements were not saved for the current account")
		}
		return nil
	}
	dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
		if request.Command == "status" {
			return clientruntime.Status{Running: true, Connected: true}, nil
		}
		events = append(events, "connect:"+request.NodeID)
		return clientruntime.Status{Running: true, Connected: true, NodeID: request.NodeID}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"connect", "--best", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != 0 || !reflect.DeepEqual(events, []string{"probe", "save", "connect:n2"}) {
		t.Fatalf("best stale cache = code %d events %v output %q / %q", code, events, stdout.String(), stderr.String())
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}

func TestProbeCommandPartialBudgetSavedButCallerCancellationIsNot(t *testing.T) {
	for _, scenario := range []string{"budget", "caller-canceled", "save-failure"} {
		t.Run(scenario, func(t *testing.T) {
			nodes := managedFixtureNodes()
			dependencies := managedDependencies(t, nodes, nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			measurement := *managedFixtureLatency(nodes[0], 8, time.Now())
			dependencies.probeNodes = func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
				if scenario == "caller-canceled" {
					cancel()
					return []nodemgr.Latency{measurement}, context.Canceled
				}
				return []nodemgr.Latency{measurement}, errors.Join(nodemgr.ErrProbeBudgetExceeded, context.DeadlineExceeded)
			}
			saves := 0
			dependencies.saveLatencies = func(_ context.Context, directory, account string, results []nodemgr.Latency) error {
				saves++
				if directory != filepath.Join("private", "test-config") || account != "public-test-account" || !reflect.DeepEqual(results, []nodemgr.Latency{measurement}) {
					t.Fatal("partial measurements were not preserved intact for the account")
				}
				if scenario == "save-failure" {
					return errors.New(clientFixtureSecret)
				}
				return nil
			}
			var stdout, stderr bytes.Buffer
			code := run(ctx, []string{"probe", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			switch scenario {
			case "budget":
				var views []nodeView
				if code != 0 || saves != 1 || json.Unmarshal(stdout.Bytes(), &views) != nil || len(views) != len(nodes) || views[0].ID != "n1" || views[0].Reachable == nil || !*views[0].Reachable || views[1].Reachable != nil || !strings.Contains(stderr.String(), "保留已完成结果") {
					t.Fatalf("partial budget = code %d saves %d output %q / %q", code, saves, stdout.String(), stderr.String())
				}
			case "caller-canceled":
				if code != exitCancelled || saves != 0 || stdout.Len() != 0 || stderr.String() != "操作已取消。\n" {
					t.Fatalf("canceled probe = code %d saves %d output %q / %q", code, saves, stdout.String(), stderr.String())
				}
			case "save-failure":
				if code != exitFailure || saves != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "保存结果失败") || strings.Contains(stderr.String(), "保留已完成结果") {
					t.Fatalf("failed save = code %d saves %d output %q / %q", code, saves, stdout.String(), stderr.String())
				}
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestNodeManagementInvalidParametersDoNotEchoSensitiveValues(t *testing.T) {
	for _, args := range [][]string{
		{"favorite", clientFixtureSecret},
		{"favorite", "add", "--unknown=" + clientFixtureSecret},
		{"probe", "--timeout=" + clientFixtureSecret},
		{"nodes", "--sort=" + clientFixtureSecret},
		{"connect", "--concurrency=" + clientFixtureSecret},
	} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, cliDependencies{})
		if code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("invalid management args = code %d output %q / %q", code, stdout.String(), stderr.String())
		}
		assertClientOutputSafe(t, &stdout, &stderr)
	}
}
