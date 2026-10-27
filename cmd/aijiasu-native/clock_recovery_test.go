package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
)

func TestBestRecoversAfterClockRollbackAndIgnoresLateFutureBatch(t *testing.T) {
	options := recoveryOptions(t)
	node, address := recoveryNode(t, "clock-rollback")
	serveRecoveredNode(t, address)
	session := clientapi.Session{Username: "public-clock-account"}
	future, err := nodemgr.Probe(context.Background(), []clientapi.Node{node}, nodemgr.ProbeConfig{
		Attempts: 1, Timeout: time.Second, Budget: time.Second,
		Now: func() time.Time { return time.Now().Add(10 * time.Minute) },
	})
	if err != nil || len(future) != 1 || !future[0].Reachable {
		t.Fatal("local listener did not produce an injected-clock measurement")
	}
	// This is an on-disk snapshot written while the earlier clock was ahead.
	// No test changes the host's wall clock or network configuration.
	state := nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{
		node.ID: {ID: node.ID, Favorite: true, UseCount: 2, Latency: &future[0]},
	}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(session.Username))
	name := "nodes-" + hex.EncodeToString(hash[:]) + ".json"
	if err := os.WriteFile(filepath.Join(options.directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies := defaultDependencies()
	candidates, err := connectionCandidates(context.Background(), []clientapi.Node{node}, "", options, session, io.Discard, dependencies)
	if err != nil || len(candidates) != 1 || candidates[0].ID != node.ID {
		t.Fatal("clock rollback prevented automatic selection of a reachable node")
	}
	current, err := nodemgr.Load(options.directory, session.Username)
	if err != nil {
		t.Fatal(err)
	}
	accepted := *current.Entries[node.ID].Latency
	if nodemgr.IsFutureLatency(accepted.CheckedAt, time.Now()) || !current.Entries[node.ID].Favorite || current.Entries[node.ID].UseCount != 2 {
		t.Fatal("clock recovery failed to replace timing or preserve preferences")
	}
	// A delayed batch may carry the former clock's timestamp even after a
	// current successful batch has committed. Neither disk nor CLI may reuse it.
	dependencies.probeNodes = func(ctx context.Context, nodes []clientapi.Node, config nodemgr.ProbeConfig) ([]nodemgr.Latency, error) {
		config.Now = func() time.Time { return time.Now().Add(10 * time.Minute) }
		return nodemgr.Probe(ctx, nodes, config)
	}
	options.testLatency = true
	candidates, err = connectionCandidates(context.Background(), []clientapi.Node{node}, "", options, session, io.Discard, dependencies)
	if err != nil || len(candidates) != 1 || candidates[0].ID != node.ID {
		t.Fatal("late future batch hid the latest valid committed candidate")
	}
	after, err := nodemgr.Load(options.directory, session.Username)
	if err != nil || after.Entries[node.ID].Latency == nil || *after.Entries[node.ID].Latency != accepted {
		t.Fatal("late future batch poisoned the recovered cache")
	}
}
