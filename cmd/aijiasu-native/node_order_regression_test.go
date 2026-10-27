package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
)

func TestNameSortUsesIDForEveryCaseInsensitiveTie(t *testing.T) {
	fixtures := []clientapi.Node{
		{ID: "2", Title: "Foo"},
		{ID: "1", Title: "foo"},
		{ID: "0", Title: "Foo"},
	}
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			nodes := []clientapi.Node{fixtures[order[0]], fixtures[order[1]], fixtures[order[2]]}
			dependencies := managedDependencies(t, nodes, nodemgr.State{})
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"nodes", "--sort", "name", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			var views []nodeView
			if code != 0 || json.Unmarshal(stdout.Bytes(), &views) != nil || stderr.Len() != 0 {
				t.Fatal("name sorting failed")
			}
			var ids []string
			for _, view := range views {
				ids = append(ids, view.ID)
			}
			if !reflect.DeepEqual(ids, []string{"0", "1", "2"}) {
				t.Fatalf("case-insensitive ties = %v, want IDs [0 1 2]", ids)
			}
		})
	}
}

func TestRecentProbeLimitsKeepTheMostRecentlyUsedCandidates(t *testing.T) {
	now := time.Now().UTC()
	nodes := make([]clientapi.Node, 25)
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
	for index := range nodes {
		id := fmt.Sprintf("n%02d", index)
		nodes[index] = clientapi.Node{ID: id, Title: id, Host: "one.example.test", TCPPort: 443}
		state.Entries[id] = nodemgr.Entry{ID: id, LastUsedAt: now.Add(-time.Duration(len(nodes)-index) * time.Second), UseCount: uint64(index + 1)}
	}
	latest := make([]string, 20)
	for index := range latest {
		latest[index] = nodes[len(nodes)-1-index].ID
	}
	for _, test := range []struct {
		name string
		args []string
		ids  []string
	}{
		{"explicit-limit", []string{"recent", "--test", "--limit", "1", "--json"}, latest[:1]},
		{"default-limit", []string{"recent", "--test", "--json"}, latest},
		{"recent-filter", []string{"nodes", "--recent", "--test", "--limit", "2", "--json"}, latest[:2]},
		{"explicit-sort", []string{"nodes", "--sort", "recent", "--test", "--limit", "2", "--json"}, latest[:2]},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertProbeCandidateOrder(t, slices.Clone(nodes), state, test.args, test.ids, test.ids)
		})
	}
}

func TestProbeCandidateOrderHonorsNameAndIDButSortsLatencyAfterMeasuring(t *testing.T) {
	nodes := []clientapi.Node{
		{ID: "2", Title: "Zulu", Host: "one.example.test", TCPPort: 443},
		{ID: "1", Title: "beta", Host: "two.example.test", TCPPort: 443},
		{ID: "0", Title: "Alpha", Host: "three.example.test", TCPPort: 443},
	}
	for _, test := range []struct {
		name    string
		args    []string
		probed  []string
		display []string
	}{
		{"name", []string{"nodes", "--test", "--sort", "name", "--limit", "2", "--json"}, []string{"0", "1"}, []string{"0", "1"}},
		{"id", []string{"nodes", "--test", "--sort", "id", "--limit", "2", "--json"}, []string{"0", "1"}, []string{"0", "1"}},
		{"latency", []string{"nodes", "--test", "--sort", "latency", "--limit", "2", "--json"}, []string{"2", "1"}, []string{"1", "2"}},
		{"probe-default", []string{"probe", "--limit", "2", "--json"}, []string{"2", "1"}, []string{"1", "2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
			for _, node := range nodes {
				state.Entries[node.ID] = nodemgr.Entry{ID: node.ID}
			}
			assertProbeCandidateOrder(t, slices.Clone(nodes), state, test.args, test.probed, test.display)
		})
	}
}

func assertProbeCandidateOrder(t *testing.T, nodes []clientapi.Node, state nodemgr.State, args, expectedProbe, expectedDisplay []string) {
	t.Helper()
	dependencies := managedDependencies(t, nodes, state)
	var probed []string
	dependencies.probeNodes = func(_ context.Context, candidates []clientapi.Node, _ nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		results := make([]nodemgr.Latency, len(candidates))
		for index, node := range candidates {
			probed = append(probed, node.ID)
			results[index] = *managedFixtureLatency(node, float64(len(candidates)-index), time.Now().UTC())
		}
		return results, nil
	}
	dependencies.saveLatencies = func(_ context.Context, _, _ string, results []nodemgr.Latency) error {
		for _, result := range results {
			entry := state.Entries[result.ID]
			entry.Latency = &result
			state.Entries[result.ID] = entry
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	var views []nodeView
	if code != 0 || json.Unmarshal(stdout.Bytes(), &views) != nil || stderr.Len() != 0 {
		t.Fatalf("probe list failed: code %d, %q / %q", code, stdout.String(), stderr.String())
	}
	var displayed []string
	for _, view := range views {
		displayed = append(displayed, view.ID)
		if view.Reachable == nil || !*view.Reachable || view.LatencyMS == nil || !view.LatencyFresh {
			t.Fatal("display did not use the new measurement")
		}
		entry := state.Entries[view.ID]
		if view.UseCount != entry.UseCount || !entry.LastUsedAt.IsZero() && (view.LastUsedAt == nil || !view.LastUsedAt.Equal(entry.LastUsedAt)) {
			t.Fatal("probing lost the recent-use metadata")
		}
	}
	if !reflect.DeepEqual(probed, expectedProbe) || !reflect.DeepEqual(displayed, expectedDisplay) {
		t.Fatalf("probed %v / displayed %v, want %v / %v", probed, displayed, expectedProbe, expectedDisplay)
	}
}
