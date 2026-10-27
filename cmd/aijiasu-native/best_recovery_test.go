package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
)

func recoveryNode(t *testing.T, id string) (clientapi.Node, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return clientapi.Node{ID: id, Host: "127.0.0.1", TCPPort: port}, address
}

func serveRecoveredNode(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
}

func failedRecoveryMeasurement(t *testing.T, node clientapi.Node) nodemgr.Latency {
	t.Helper()
	results, err := nodemgr.Probe(context.Background(), []clientapi.Node{node}, nodemgr.ProbeConfig{
		Attempts: 1, Timeout: 100 * time.Millisecond, Budget: time.Second,
	})
	if err != nil || len(results) != 1 || results[0].Reachable {
		t.Fatal("closed local port did not produce a completed failed measurement")
	}
	return results[0]
}

func recoveryOptions(t *testing.T) clientOptions {
	t.Helper()
	directory := privateCLIStateDirectory(t)
	return clientOptions{directory: directory, best: true, probeTimeout: 100 * time.Millisecond,
		probeBudget: time.Second, concurrency: 1}
}

func TestBestReprobesRecoveredNodeWithoutForcedTestAndThenReusesSuccess(t *testing.T) {
	options := recoveryOptions(t)
	node, address := recoveryNode(t, "recovered")
	session := clientapi.Session{Username: "public-recovery-account"}
	failed := failedRecoveryMeasurement(t, node)
	if err := nodemgr.SaveLatencies(options.directory, session.Username, []nodemgr.Latency{failed}); err != nil {
		t.Fatal(err)
	}
	serveRecoveredNode(t, address)
	dependencies := defaultDependencies()
	probes := 0
	dependencies.probeNodes = func(ctx context.Context, nodes []clientapi.Node, config nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		probes++
		if len(nodes) != 1 || nodes[0].ID != node.ID {
			t.Fatal("automatic recovery probed an unexpected node")
		}
		return nodemgr.Probe(ctx, nodes, config)
	}
	for attempt := range 2 {
		candidates, err := connectionCandidates(context.Background(), []clientapi.Node{node}, "", options, session, io.Discard, dependencies)
		if err != nil || len(candidates) != 1 || candidates[0].ID != node.ID || probes != 1 {
			t.Fatalf("recovered node selection %d failed or ignored the fresh successful cache", attempt)
		}
	}
	state, err := nodemgr.Load(options.directory, session.Username)
	if err != nil {
		t.Fatal(err)
	}
	measurement := state.Entries[node.ID].Latency
	if measurement == nil || !measurement.Reachable || !measurement.CheckedAt.After(failed.CheckedAt) {
		t.Fatal("automatic recovery did not persist a new successful measurement")
	}
}

func TestBestReprobesFreshFailureOnEverySelectionWithoutUsingFailedZero(t *testing.T) {
	options := recoveryOptions(t)
	node, _ := recoveryNode(t, "still-unreachable")
	session := clientapi.Session{Username: "public-recovery-account"}
	failed := failedRecoveryMeasurement(t, node)
	if err := nodemgr.SaveLatencies(options.directory, session.Username, []nodemgr.Latency{failed}); err != nil {
		t.Fatal(err)
	}
	dependencies := defaultDependencies()
	probes := 0
	dependencies.probeNodes = func(ctx context.Context, nodes []clientapi.Node, config nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		probes++
		return nodemgr.Probe(ctx, nodes, config)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		candidates, err := connectionCandidates(context.Background(), []clientapi.Node{node}, "", options, session, io.Discard, dependencies)
		if err == nil || len(candidates) != 0 || probes != attempt {
			t.Fatal("automatic selection reused a fresh failure or selected its zero timing")
		}
	}
	state, err := nodemgr.Load(options.directory, session.Username)
	if err != nil {
		t.Fatal(err)
	}
	measurement := state.Entries[node.ID].Latency
	if measurement == nil || measurement.Reachable || measurement.Attempts != 2 || !measurement.CheckedAt.After(failed.CheckedAt) {
		t.Fatal("automatic retry did not preserve the new failed probe result")
	}
}

func TestBestMixedCacheReprobesOnlyFailuresAndKeepsFreshSuccess(t *testing.T) {
	options := recoveryOptions(t)
	recovered, address := recoveryNode(t, "recovered")
	cached, _ := recoveryNode(t, "cached-success")
	nodes := []clientapi.Node{cached, recovered}
	session := clientapi.Session{Username: "public-recovery-account"}
	failed := failedRecoveryMeasurement(t, recovered)
	success := managedFixtureLatency(cached, 60_000, time.Now())
	if err := nodemgr.SaveLatencies(options.directory, session.Username, []nodemgr.Latency{*success, failed}); err != nil {
		t.Fatal(err)
	}
	serveRecoveredNode(t, address)
	dependencies := defaultDependencies()
	probes := 0
	dependencies.probeNodes = func(ctx context.Context, nodes []clientapi.Node, config nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		probes++
		if len(nodes) != 1 || nodes[0].ID != recovered.ID {
			t.Fatal("mixed cache did not limit retry to the failed node")
		}
		return nodemgr.Probe(ctx, nodes, config)
	}
	candidates, err := connectionCandidates(context.Background(), nodes, "", options, session, io.Discard, dependencies)
	if err != nil || len(candidates) != 2 || candidates[0].ID != recovered.ID || candidates[1].ID != cached.ID || probes != 1 {
		t.Fatal("mixed cache did not select the recovered node alongside the cached successful node")
	}
	state, err := nodemgr.Load(options.directory, session.Username)
	if err != nil {
		t.Fatal(err)
	}
	measurement := state.Entries[cached.ID].Latency
	if measurement == nil || !measurement.CheckedAt.Equal(success.CheckedAt) || measurement.Milliseconds != success.Milliseconds {
		t.Fatal("failure recovery changed the fresh successful cache")
	}
}
