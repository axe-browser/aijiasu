package nodemgr

import (
	"reflect"
	"testing"
	"time"
)

func TestCurrentLatencyReplacesFutureCacheAndRejectsDelayedFutureBatch(t *testing.T) {
	directory := privateStateDirectory(t)
	now := time.Now().UTC()
	original := fixtureLatency("node")
	original.CheckedAt = now.Add(10 * time.Minute)
	state := State{Version: 1, Entries: map[string]Entry{
		"node": {ID: "node", Favorite: true, UseCount: 4, LastUsedAt: now.Add(-time.Minute), Latency: &original},
	}}
	writeStateFixture(t, directory, stateTestAccount, state)
	current := original
	current.CheckedAt, current.Milliseconds = now, 8
	if err := SaveLatencies(directory, stateTestAccount, []Latency{current}); err != nil {
		t.Fatal(err)
	}
	recovered, err := Load(directory, stateTestAccount)
	if err != nil || recovered.Entries["node"].Latency == nil || *recovered.Entries["node"].Latency != current {
		t.Fatal("current successful timing could not replace the old clock's future timing")
	}
	entry := recovered.Entries["node"]
	if !entry.Favorite || entry.UseCount != 4 || !entry.LastUsedAt.Equal(state.Entries["node"].LastUsedAt) {
		t.Fatal("clock recovery lost node preferences or recent history")
	}
	for _, future := range []Latency{original, {ID: "future-only", Host: "node.example.test", Port: 443, CheckedAt: now.Add(time.Hour), Attempts: 1}} {
		if err := SaveLatencies(directory, stateTestAccount, []Latency{future}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := Load(directory, stateTestAccount)
	if err != nil || !reflect.DeepEqual(after, recovered) {
		t.Fatal("a delayed future batch changed valid recovered timings")
	}
	older := current
	older.CheckedAt, older.Milliseconds = now.Add(-time.Second), 1
	if err := SaveLatencies(directory, stateTestAccount, []Latency{older}); err != nil {
		t.Fatal(err)
	}
	after, err = Load(directory, stateTestAccount)
	if err != nil || !reflect.DeepEqual(after, recovered) {
		t.Fatal("clock recovery weakened normal timestamp ordering")
	}
}

func TestMixedLatencyBatchDropsOnlyImplausibleFutureMeasurements(t *testing.T) {
	directory := privateStateDirectory(t)
	now := time.Now().UTC()
	valid := fixtureLatency("valid")
	valid.CheckedAt = now
	smallCorrection := fixtureLatency("small-correction")
	smallCorrection.CheckedAt = now.Add(LatencyFutureTolerance / 2)
	future := fixtureLatency("discarded")
	future.CheckedAt = now.Add(10 * LatencyFutureTolerance)
	if err := SaveLatencies(directory, stateTestAccount, []Latency{valid, future, smallCorrection}); err != nil {
		t.Fatal(err)
	}
	state, err := Load(directory, stateTestAccount)
	if err != nil || len(state.Entries) != 2 || state.Entries["valid"].Latency == nil || state.Entries["small-correction"].Latency == nil {
		t.Fatal("mixed batch discarded valid clock-tolerant measurements")
	}
	if _, exists := state.Entries["discarded"]; exists {
		t.Fatal("mixed batch persisted an implausible future measurement")
	}
	if IsFutureLatency(now.Add(LatencyFutureTolerance), now) || !IsFutureLatency(now.Add(LatencyFutureTolerance+time.Nanosecond), now) {
		t.Fatal("future timestamp policy disagrees at its shared tolerance boundary")
	}
}
