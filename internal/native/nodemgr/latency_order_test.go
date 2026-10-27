package nodemgr

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestLatencyCommitKeepsNewestMeasurementAndOtherFields(t *testing.T) {
	for _, scenario := range []string{"older", "same-time", "older-endpoint", "same-time-endpoint", "newer", "newer-endpoint"} {
		t.Run(scenario, func(t *testing.T) {
			directory := privateStateDirectory(t)
			original := fixtureLatency("node-a")
			if err := SetFavorite(directory, stateTestAccount, original.ID, true); err != nil {
				t.Fatal(err)
			}
			if err := RecordUse(directory, stateTestAccount, original.ID, original.CheckedAt); err != nil {
				t.Fatal(err)
			}
			if err := SaveLatencies(directory, stateTestAccount, []Latency{original}); err != nil {
				t.Fatal(err)
			}
			candidate := original
			candidate.Milliseconds, candidate.Successes, candidate.Reachable = 0, 0, false
			candidate.Error = "TCP connection failed"
			switch scenario {
			case "older", "older-endpoint":
				candidate.CheckedAt = original.CheckedAt.Add(-20 * time.Second)
			case "newer", "newer-endpoint":
				candidate.CheckedAt = original.CheckedAt.Add(20 * time.Second)
			}
			if scenario == "older-endpoint" || scenario == "same-time-endpoint" || scenario == "newer-endpoint" {
				candidate.Host, candidate.Port = "changed.example.test", 4443
			}
			if err := SaveLatencies(directory, stateTestAccount, []Latency{candidate}); err != nil {
				t.Fatal(err)
			}
			state, err := Load(directory, stateTestAccount)
			if err != nil {
				t.Fatal(err)
			}
			entry := state.Entries[original.ID]
			want := original
			if candidate.CheckedAt.After(original.CheckedAt) {
				want = candidate
			}
			if entry.Latency == nil || !reflect.DeepEqual(*entry.Latency, want) {
				t.Fatal("latency was chosen by commit order rather than measurement time")
			}
			if !entry.Favorite || entry.UseCount != 1 || !entry.LastUsedAt.Equal(original.CheckedAt) {
				t.Fatal("latency update changed favorite or recent-use data")
			}
		})
	}
}

func TestConcurrentLatencyCommitsRetainLatestTimestamp(t *testing.T) {
	directory := privateStateDirectory(t)
	original := fixtureLatency("concurrent-node")
	const writers = 8
	var workers sync.WaitGroup
	failures := make(chan error, writers)
	for index := 0; index < writers; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			measurement := original
			measurement.CheckedAt = original.CheckedAt.Add(time.Duration(index) * time.Second)
			measurement.Milliseconds = float64(index + 1)
			if err := SaveLatencies(directory, stateTestAccount, []Latency{measurement}); err != nil {
				failures <- err
			}
		}(index)
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	state, err := Load(directory, stateTestAccount)
	if err != nil {
		t.Fatal(err)
	}
	got := state.Entries[original.ID].Latency
	if got == nil || !got.CheckedAt.Equal(original.CheckedAt.Add((writers-1)*time.Second)) || got.Milliseconds != writers {
		t.Fatal("concurrent commits lost the newest measurement")
	}
}
