package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
	clientruntime "aijiasu-native/internal/native/runtime"
)

func TestBestForegroundRetriesWithIndependentClearedPasswordBuffers(t *testing.T) {
	dependencies := firstConnectDependencies(t)
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
	for index, node := range clientFixtureSession().Nodes {
		state.Entries[node.ID] = nodemgr.Entry{ID: node.ID, Latency: &nodemgr.Latency{
			ID: node.ID, Host: node.Host, Port: node.TCPPort, Milliseconds: float64(index + 1),
			CheckedAt: time.Now(), Successes: 2, Attempts: 2, Reachable: true,
		}}
	}
	dependencies.loadNodeState = func(context.Context, string, string) (nodemgr.State, error) { return state, nil }
	password := []byte(clientFixtureSecret)
	dependencies.readPassword = func(context.Context) ([]byte, error) { return password, nil }
	var tried []string
	var buffers [][]byte
	dependencies.runtimeRun = func(_ context.Context, config clientruntime.Config, id string, ready func(clientruntime.Status)) error {
		if string(config.Password) != clientFixtureSecret || config.ListenAddress != "127.0.0.1:2080" {
			t.Fatal("candidate lost original credentials or custom port")
		}
		tried = append(tried, id)
		buffers = append(buffers, config.Password)
		if len(tried) == 1 {
			clear(config.Password)
			return errors.New(clientFixtureSecret)
		}
		ready(clientruntime.Status{Running: true, Connected: true, NodeID: id, ListenAddress: config.ListenAddress})
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"connect", "--best", "--listen", "127.0.0.1:2080"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != 0 || !reflect.DeepEqual(tried, []string{"210", "211"}) {
		t.Fatalf("candidate fallback code %d, attempts %v", code, tried)
	}
	for _, buffer := range append(buffers, password) {
		if !bytes.Equal(buffer, make([]byte, len(buffer))) {
			t.Fatal("candidate retained password bytes")
		}
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}

func TestBestForcedProbeBudgetDoesNotReuseUnmeasuredFreshCache(t *testing.T) {
	dependencies := clientCommandDependencies(t)
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}
	for index, node := range clientFixtureSession().Nodes {
		state.Entries[node.ID] = nodemgr.Entry{ID: node.ID, Latency: &nodemgr.Latency{ID: node.ID, Host: node.Host, Port: node.TCPPort, Milliseconds: float64(index + 1), CheckedAt: time.Now(), Successes: 2, Attempts: 2, Reachable: true}}
	}
	dependencies.loadNodeState = func(context.Context, string, string) (nodemgr.State, error) { return state, nil }
	dependencies.probeNodes = func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		measurement := *state.Entries["211"].Latency
		measurement.Milliseconds = 20
		return []nodemgr.Latency{measurement}, nodemgr.ErrProbeBudgetExceeded
	}
	dependencies.saveLatencies = func(context.Context, string, string, []nodemgr.Latency) error { return nil }
	selected := ""
	dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
		if request.Command == "status" {
			return clientruntime.Status{Running: true, Connected: true, NodeID: "310"}, nil
		}
		selected = request.NodeID
		return clientruntime.Status{Running: true, Connected: true, NodeID: request.NodeID}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"switch", "--best", "--test"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != 0 || selected != "211" {
		t.Fatalf("forced probe selected stale cached node: code %d node %s", code, selected)
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}
