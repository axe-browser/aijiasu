package nodemgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"aijiasu-native/internal/native/privatefile"
)

const stateTestAccount = "public-isolated-account@example.test"

func privateStateDirectory(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("node-state locking requires macOS, Linux or Windows")
	}
	directory := filepath.Join(t.TempDir(), "private")
	if err := privatefile.MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func fixtureLatency(id string) Latency {
	return Latency{ID: id, Host: "node.example.test", Port: 443, Milliseconds: 12.5, CheckedAt: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), Attempts: 2, Successes: 2, Reachable: true}
}

func writeStateFixture(t *testing.T, directory, account string, state State) string {
	t.Helper()
	name, _, err := accountNames(account)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStateAccountIsolationAndPreservedFields(t *testing.T) {
	directory := privateStateDirectory(t)
	empty, err := Load(filepath.Join(directory, "missing"), stateTestAccount)
	if err != nil || empty.Version != 1 || empty.Entries == nil || len(empty.Entries) != 0 {
		t.Fatal("missing state did not produce an empty V1 map")
	}
	if err := SetFavorite(directory, stateTestAccount, "node-a", true); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	if err := RecordUse(directory, stateTestAccount, "node-a", at); err != nil {
		t.Fatal(err)
	}
	if err := SaveLatencies(directory, stateTestAccount, []Latency{fixtureLatency("node-a")}); err != nil {
		t.Fatal(err)
	}
	if err := RecordUse(directory, stateTestAccount, "node-a", at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	state, err := Load(directory, stateTestAccount)
	if err != nil {
		t.Fatal(err)
	}
	entry := state.Entries["node-a"]
	if !entry.Favorite || entry.UseCount != 2 || !entry.LastUsedAt.Equal(at) || entry.Latency == nil || entry.Latency.Milliseconds != 12.5 {
		t.Fatal("independent state updates overwrote another field")
	}
	other, err := Load(directory, "another-public-account")
	if err != nil || len(other.Entries) != 0 {
		t.Fatal("account state was shared")
	}
	if err := SetFavorite(directory, "another-public-account", "node-a", false); err != nil {
		t.Fatal(err)
	}
	state, _ = Load(directory, stateTestAccount)
	if !state.Entries["node-a"].Favorite {
		t.Fatal("another account changed favorite state")
	}
	name, lockName, _ := accountNames(stateTestAccount)
	for _, fileName := range []string{name, lockName} {
		path := filepath.Join(directory, fileName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(fileName, stateTestAccount) || strings.Contains(string(data), stateTestAccount) || strings.Contains(string(data), "login_token") || strings.Contains(string(data), "password") {
			t.Fatal("state exposed account or credential material")
		}
		info, _ := os.Lstat(path)
		if !privatefile.PrivateMode(info, true) || privatefile.CheckPath(path) != nil {
			t.Fatal("node state or lock was not private")
		}
	}
}

func TestStateConcurrentUpdatesDoNotLoseFavoritesOrUses(t *testing.T) {
	directory := privateStateDirectory(t)
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for iteration := 0; iteration < 8; iteration++ {
				var err error
				if worker%2 == 0 {
					err = RecordUse(directory, stateTestAccount, "shared", time.Unix(int64(iteration), 0))
				} else {
					err = SetFavorite(directory, stateTestAccount, "shared", true)
				}
				if err != nil {
					failures <- err
					return
				}
			}
		}(worker)
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("%v (safe OS cause: %v)", err, errors.Unwrap(err))
	}
	state, err := Load(directory, stateTestAccount)
	if err != nil || !state.Entries["shared"].Favorite || state.Entries["shared"].UseCount != 32 {
		t.Fatalf("concurrent state update lost data: %v", err)
	}
}

func TestStateProcessWriter(t *testing.T) {
	directory := os.Getenv("NODEMGR_TEST_DIRECTORY")
	if directory == "" {
		return
	}
	for index := 0; index < 10; index++ {
		if err := RecordUse(directory, stateTestAccount, "cross-process", time.Unix(int64(index), 0)); err != nil {
			t.Fatal(err)
		}
		if err := SetFavorite(directory, stateTestAccount, "cross-process", true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStateCrossProcessUpdatesAreSerialized(t *testing.T) {
	directory := privateStateDirectory(t)
	commands := []*exec.Cmd{exec.Command(os.Args[0], "-test.run=^TestStateProcessWriter$"), exec.Command(os.Args[0], "-test.run=^TestStateProcessWriter$")}
	for _, command := range commands {
		command.Env = append(os.Environ(), "NODEMGR_TEST_DIRECTORY="+directory)
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatal("constructed node-state writer failed")
		}
	}
	state, err := Load(directory, stateTestAccount)
	if err != nil || !state.Entries["cross-process"].Favorite || state.Entries["cross-process"].UseCount != 20 {
		t.Fatalf("process updates lost data: %v", err)
	}
}

func TestStateRejectsPermissionsLinksAndMalformedJSON(t *testing.T) {
	for _, kind := range []string{"public directory", "linked directory", "public file", "linked file", "directory file", "linked lock", "malformed", "unknown", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			if runtime.GOOS == "windows" && (kind == "public directory" || kind == "public file") {
				t.Skip("Unix permission bits; Windows DACL rejection is covered separately")
			}
			directory := privateStateDirectory(t)
			name, lockName, _ := accountNames(stateTestAccount)
			path := writeStateFixture(t, directory, stateTestAccount, emptyState())
			switch kind {
			case "public directory":
				if err := os.Chmod(directory, 0o755); err != nil {
					t.Fatal(err)
				}
			case "linked directory":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(directory, link); err != nil {
					t.Skip("symlinks unavailable")
				}
				directory = link
			case "public file":
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
			case "linked file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("untouched-private-target", path); err != nil {
					t.Skip("symlinks unavailable")
				}
			case "directory file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "linked lock":
				if err := os.Symlink(name, filepath.Join(directory, lockName)); err != nil {
					t.Skip("symlinks unavailable")
				}
			case "malformed":
				if err := os.WriteFile(path, []byte(`{"version":1`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(path, []byte(`{"version":1,"entries":{},"private-value-must-not-appear":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", maxStateBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, loadErr := Load(directory, stateTestAccount)
			saveErr := SetFavorite(directory, stateTestAccount, "new-node", true)
			if loadErr == nil || saveErr == nil {
				t.Fatal("unsafe private state was accepted")
			}
			for _, err := range []error{loadErr, saveErr} {
				if strings.Contains(err.Error(), stateTestAccount) || strings.Contains(err.Error(), "private-value-must-not-appear") {
					t.Fatal("state error leaked parsed input")
				}
			}
		})
	}
}

func TestStateValidationAndPublishFailurePreserveOriginal(t *testing.T) {
	directory := privateStateDirectory(t)
	if err := SetFavorite(directory, stateTestAccount, "original", true); err != nil {
		t.Fatal(err)
	}
	name, _, _ := accountNames(stateTestAccount)
	path := filepath.Join(directory, name)
	original, _ := os.ReadFile(path)
	for _, change := range []func(*Latency){
		func(result *Latency) { result.Milliseconds = math.NaN() }, func(result *Latency) { result.Milliseconds = math.Inf(1) }, func(result *Latency) { result.Milliseconds = -1 },
		func(result *Latency) { result.ID = "" }, func(result *Latency) { result.ID = strings.Repeat("x", maxStateIDBytes+1) }, func(result *Latency) { result.Error = "unsafe\nvalue" },
		func(result *Latency) { result.Successes = 3 }, func(result *Latency) { result.Port = 65536 },
	} {
		result := fixtureLatency("new")
		change(&result)
		if err := SaveLatencies(directory, stateTestAccount, []Latency{result}); err == nil {
			t.Fatal("invalid latency was accepted")
		}
		current, _ := os.ReadFile(path)
		if string(current) != string(original) {
			t.Fatal("invalid update changed original state")
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = publishState(root, name, []byte(`{"version":1,"entries":{}}`), func(string, string) error { return errors.New("private-rename-error") })
	if err == nil || strings.Contains(err.Error(), "private-rename-error") {
		t.Fatal("publish failure was ignored or leaked")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(original) {
		t.Fatal("failed publication changed original state")
	}
	files, _ := os.ReadDir(directory)
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".nodes-") {
			t.Fatal("failed update retained temporary file")
		}
	}
}

func TestStateEvictionPreservesFavoritesAndAllowsFutureUpdates(t *testing.T) {
	directory := privateStateDirectory(t)
	state := emptyState()
	for index := 0; index < maxStateEntries; index++ {
		id := fmt.Sprintf("n%05d", index)
		state.Entries[id] = Entry{ID: id, Favorite: index == 0}
	}
	writeStateFixture(t, directory, stateTestAccount, state)
	if err := RecordUse(directory, stateTestAccount, "newest", time.Now()); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory, stateTestAccount)
	if err != nil || len(loaded.Entries) != maxStateEntries || !loaded.Entries["n00000"].Favorite || loaded.Entries["newest"].UseCount != 1 {
		t.Fatal("bounded state failed to preserve favorite and newest update")
	}
	for id, entry := range loaded.Entries {
		entry.Favorite = true
		loaded.Entries[id] = entry
	}
	path := writeStateFixture(t, directory, stateTestAccount, loaded)
	original, _ := os.ReadFile(path)
	if err := SetFavorite(directory, stateTestAccount, "cannot-drop-favorites", true); err == nil {
		t.Fatal("full favorite cache was silently discarded")
	}
	if err := RecordUse(directory, stateTestAccount, "cannot-fit", time.Now()); err == nil {
		t.Fatal("full favorite cache falsely accepted a new entry")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(original) {
		t.Fatal("full favorite failure changed state")
	}
	if err := SetFavorite(directory, stateTestAccount, "n00000", false); err != nil {
		t.Fatal(err)
	}
	if err := RecordUse(directory, stateTestAccount, "fits-after-unfavorite", time.Now()); err != nil {
		t.Fatal("cache remained permanently unusable after releasing a favorite")
	}
	loaded, _ = Load(directory, stateTestAccount)
	if loaded.Entries["fits-after-unfavorite"].UseCount != 1 {
		t.Fatal("new entry was silently evicted")
	}
}

func TestStateByteLimitAndCountSaturation(t *testing.T) {
	state := emptyState()
	protected := make(map[string]bool)
	for index := 0; index < 150; index++ {
		id := fmt.Sprintf("%03d-", index) + strings.Repeat("x", 16000)
		state.Entries[id] = Entry{ID: id}
		protected[id] = true
	}
	if err := boundState(&state, protected); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxStateBytes || len(state.Entries) == 150 {
		t.Fatal("exact serialized byte limit was not enforced")
	}
	directory := privateStateDirectory(t)
	saturated := emptyState()
	at := time.Unix(100, 0).UTC()
	saturated.Entries["saturated"] = Entry{ID: "saturated", UseCount: math.MaxUint64, LastUsedAt: at}
	writeStateFixture(t, directory, stateTestAccount, saturated)
	if err := RecordUse(directory, stateTestAccount, "saturated", at.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory, stateTestAccount)
	if err != nil || loaded.Entries["saturated"].UseCount != math.MaxUint64 || !loaded.Entries["saturated"].LastUsedAt.Equal(at) {
		t.Fatal("counter wrapped or recent-use time regressed")
	}
}

func TestStateLockWaitIsBounded(t *testing.T) {
	directory := privateStateDirectory(t)
	root, err := openStateDirectory(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, lockName, _ := accountNames(stateTestAccount)
	lock, err := acquireStateLock(root, lockName, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlockState(lock); _ = lock.Close() }()
	started := time.Now()
	err = SetFavorite(directory, stateTestAccount, "busy", true)
	if err == nil || !strings.Contains(err.Error(), "busy") || time.Since(started) > 3*time.Second {
		t.Fatalf("lock acquisition did not end within its fixed budget: %v", err)
	}
}
