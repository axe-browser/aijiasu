package nodemgr

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"aijiasu-native/internal/native/privatefile"
)

const (
	stateVersion       = 1
	maxStateBytes      = 4 << 20
	maxStateEntries    = 10000
	maxStateIDBytes    = 16 << 10
	maxStateErrorBytes = 512
)

type Entry struct {
	ID         string    `json:"id"`
	Favorite   bool      `json:"favorite"`
	LastUsedAt time.Time `json:"last_used_at,omitempty,omitzero"`
	UseCount   uint64    `json:"use_count"`
	Latency    *Latency  `json:"latency,omitempty"`
}

type State struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

func emptyState() State { return State{Version: stateVersion, Entries: make(map[string]Entry)} }

func accountNames(account string) (string, string, error) {
	if strings.TrimSpace(account) == "" || len(account) > 64<<10 || !utf8.ValidString(account) || strings.ContainsAny(account, "\r\n\x00") {
		return "", "", errors.New("invalid node-state account")
	}
	hash := sha256.Sum256([]byte(account))
	base := "nodes-" + hex.EncodeToString(hash[:])
	return base + ".json", base + ".lock", nil
}

// Load returns a private account-isolated snapshot. No file stores the account
// name, credentials or raw service responses. Missing state is an empty V1 map.
func Load(directory, account string) (State, error) {
	return LoadContext(context.Background(), directory, account)
}

// LoadContext lets interactive commands cancel a wait for a concurrent writer.
func LoadContext(ctx context.Context, directory, account string) (State, error) {
	if ctx == nil {
		return State{}, errors.New("node-state context is required")
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	name, lockName, err := accountNames(account)
	if err != nil {
		return State{}, err
	}
	root, err := openStateDirectory(directory, false)
	if errors.Is(err, os.ErrNotExist) {
		return emptyState(), nil
	}
	if err != nil {
		return State{}, err
	}
	defer root.Close()
	info, err := stateFileInfo(root, name)
	if err != nil {
		return State{}, err
	}
	if info == nil {
		return emptyState(), nil
	}
	lock, err := acquireStateLockContext(ctx, root, lockName, false)
	if err != nil {
		return State{}, err
	}
	defer func() { _ = unlockState(lock); _ = lock.Close() }()
	state, err := loadState(root, name)
	if ctx.Err() != nil {
		return State{}, ctx.Err()
	}
	return state, err
}

func SetFavorite(directory, account, id string, favorite bool) error {
	return SetFavoriteContext(context.Background(), directory, account, id, favorite)
}

// SetFavoriteContext stops waiting or publishing when its caller is canceled.
func SetFavoriteContext(ctx context.Context, directory, account, id string, favorite bool) error {
	if ctx == nil {
		return errors.New("node-state context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validStateID(id) {
		return errors.New("invalid node-state identifier")
	}
	return updateStateContext(ctx, directory, account, func(state *State) map[string]bool {
		entry, exists := state.Entries[id]
		if !exists && !favorite {
			return nil
		}
		entry.ID, entry.Favorite = id, favorite
		state.Entries[id] = entry
		return map[string]bool{id: true}
	})
}

func RecordUse(directory, account, id string, at time.Time) error {
	if !validStateID(id) {
		return errors.New("invalid node-state identifier")
	}
	if _, err := at.MarshalJSON(); err != nil {
		return errors.New("invalid node-use timestamp")
	}
	return updateState(directory, account, func(state *State) map[string]bool {
		entry := state.Entries[id]
		entry.ID = id
		if at.After(entry.LastUsedAt) {
			entry.LastUsedAt = at.UTC()
		}
		// Count saturation avoids wrapping a valid persisted uint64 to zero.
		if entry.UseCount < math.MaxUint64 {
			entry.UseCount++
		}
		state.Entries[id] = entry
		return map[string]bool{id: true}
	})
}

func SaveLatencies(directory, account string, results []Latency) error {
	return SaveLatenciesContext(context.Background(), directory, account, results)
}

// SaveLatenciesContext keeps canceled probe batches out of persisted state.
func SaveLatenciesContext(ctx context.Context, directory, account string, results []Latency) error {
	if ctx == nil {
		return errors.New("node-state context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(results) > maxStateEntries {
		return errors.New("node latency results exceed resource limits")
	}
	seen := make(map[string]bool, len(results))
	fieldBytes := 0
	for _, result := range results {
		if seen[result.ID] || !validLatency(result) {
			return errors.New("invalid node latency result")
		}
		seen[result.ID] = true
		fieldBytes += len(result.ID) + len(result.Host) + len(result.Error)
		if fieldBytes > maxStateBytes {
			return errors.New("node latency results exceed resource limits")
		}
	}
	return updateStateContext(ctx, directory, account, func(state *State) map[string]bool {
		now := time.Now()
		protected := make(map[string]bool, len(results))
		for _, result := range results {
			// A batch that completed before the clock moved back must not poison
			// current timings when it eventually obtains the persistence lock.
			if IsFutureLatency(result.CheckedAt, now) {
				continue
			}
			protected[result.ID] = true
			entry := state.Entries[result.ID]
			// Probes commit in batches, so completion order can differ from write
			// order. Keep the first result on ties, including endpoint changes;
			// implausible future cache entries cannot block clock recovery.
			if entry.Latency != nil && !IsFutureLatency(entry.Latency.CheckedAt, now) && !result.CheckedAt.After(entry.Latency.CheckedAt) {
				continue
			}
			entry.ID = result.ID
			result.CheckedAt = result.CheckedAt.UTC()
			copy := result
			entry.Latency = &copy
			state.Entries[result.ID] = entry
		}
		return protected
	})
}

func updateState(directory, account string, update func(*State) map[string]bool) error {
	return updateStateContext(context.Background(), directory, account, update)
}

func updateStateContext(ctx context.Context, directory, account string, update func(*State) map[string]bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, lockName, err := accountNames(account)
	if err != nil {
		return err
	}
	root, err := openStateDirectory(directory, true)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := acquireStateLockContext(ctx, root, lockName, true)
	if err != nil {
		return err
	}
	defer func() { _ = unlockState(lock); _ = lock.Close() }()
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := loadState(root, name)
	if err != nil {
		return err
	}
	protected := update(&state)
	if err := boundState(&state, protected); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxStateBytes {
		return errors.New("node state exceeds serialization limits")
	}
	return publishStateContext(ctx, root, name, data, root.Rename)
}

func loadState(root *os.Root, name string) (State, error) {
	info, err := stateFileInfo(root, name)
	if err != nil {
		return State{}, err
	}
	if info == nil {
		return emptyState(), nil
	}
	file, err := root.Open(name)
	if err != nil {
		return State{}, errors.New("cannot open private node state")
	}
	defer file.Close()
	opened, statErr := file.Stat()
	current, currentErr := root.Lstat(name)
	if statErr != nil || currentErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, current) || checkStateFile(opened) != nil || checkStateFile(current) != nil {
		return State{}, errors.New("private node state changed while opening")
	}
	if err := privatefile.CheckFile(file); err != nil {
		return State{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil || len(data) > maxStateBytes {
		return State{}, errors.New("cannot read bounded private node state")
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Version != stateVersion || state.Entries == nil || len(state.Entries) > maxStateEntries {
		return State{}, errors.New("invalid private node-state JSON")
	}
	for id, entry := range state.Entries {
		if !validStateID(id) || entry.ID != id || entry.Latency != nil && (entry.Latency.ID != id || !validLatency(*entry.Latency)) {
			return State{}, errors.New("invalid private node-state entry")
		}
	}
	return state, nil
}

func validStateID(id string) bool {
	return id != "" && len(id) <= maxStateIDBytes && utf8.ValidString(id) && !strings.ContainsFunc(id, unicode.IsControl)
}

func validLatency(result Latency) bool {
	if !validStateID(result.ID) || len(result.Host) > maxStateIDBytes || !utf8.ValidString(result.Host) || strings.ContainsFunc(result.Host, unicode.IsControl) || result.Port < 0 || result.Port > 65535 || math.IsNaN(result.Milliseconds) || math.IsInf(result.Milliseconds, 0) || result.Milliseconds < 0 || result.Attempts < 0 || result.Attempts > 10 || result.Successes < 0 || result.Successes > result.Attempts || len(result.Error) > maxStateErrorBytes || !utf8.ValidString(result.Error) || strings.ContainsFunc(result.Error, unicode.IsControl) {
		return false
	}
	if result.Reachable && (result.Successes == 0 || result.Host == "" || result.Port == 0) || !result.Reachable && result.Successes != 0 {
		return false
	}
	_, err := result.CheckedAt.MarshalJSON()
	return err == nil
}

type evictionCandidate struct {
	id        string
	cost      int
	protected bool
	activity  time.Time
}

// Bound both entries and exact JSON bytes without first allocating a potentially
// oversized whole-state serialization. Favorites are never eviction candidates.
func boundState(state *State, protected map[string]bool) error {
	empty, _ := json.Marshal(emptyState())
	sum, count := 0, len(state.Entries)
	candidates := make([]evictionCandidate, 0, count)
	for id, entry := range state.Entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			return errors.New("invalid node-state serialization")
		}
		key, _ := json.Marshal(id)
		cost := len(key) + 1 + len(encoded)
		sum += cost
		if !entry.Favorite {
			activity := entry.LastUsedAt
			if entry.Latency != nil && entry.Latency.CheckedAt.After(activity) {
				activity = entry.Latency.CheckedAt
			}
			candidates = append(candidates, evictionCandidate{id, cost, protected[id], activity})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.protected != right.protected {
			return !left.protected
		}
		if !left.activity.Equal(right.activity) {
			return left.activity.Before(right.activity)
		}
		return left.id < right.id
	})
	size := func() int {
		if count == 0 {
			return len(empty)
		}
		return len(empty) + sum + count - 1
	}
	for _, candidate := range candidates {
		if count <= maxStateEntries && size() <= maxStateBytes {
			break
		}
		delete(state.Entries, candidate.id)
		sum -= candidate.cost
		count--
	}
	if count > maxStateEntries || size() > maxStateBytes {
		return errors.New("node state is full of protected favorites")
	}
	if len(protected) > 0 {
		retained := false
		for id := range protected {
			if _, exists := state.Entries[id]; exists {
				retained = true
				break
			}
		}
		if !retained {
			return errors.New("node state has no capacity beyond saved favorites")
		}
	}
	return nil
}

func openStateDirectory(directory string, create bool) (*os.Root, error) {
	if directory == "" {
		return nil, errors.New("node-state directory is required")
	}
	if create {
		if err := privatefile.MkdirAll(directory); err != nil {
			return nil, errors.New("cannot create private node-state directory")
		}
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !info.IsDir() || !privatefile.PrivateMode(info, false) {
		return nil, errors.New("node-state directory must be private and not a symbolic link")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("cannot open private node-state directory")
	}
	opened, openedErr := root.Stat(".")
	current, currentErr := os.Lstat(directory)
	if openedErr != nil || currentErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, current) || !current.IsDir() || !privatefile.PrivateMode(current, false) {
		root.Close()
		return nil, errors.New("private node-state directory changed while opening")
	}
	if err := privatefile.CheckRoot(root); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func checkStateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || !privatefile.PrivateMode(info, true) || info.Size() > maxStateBytes {
		return errors.New("node state must be a bounded owner-readable private regular file")
	}
	return nil
}

func stateFileInfo(root *os.Root, name string) (os.FileInfo, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot inspect private node state")
	}
	if err := checkStateFile(info); err != nil {
		return nil, err
	}
	return info, nil
}

func acquireStateLock(root *os.Root, name string, exclusive bool) (*os.File, error) {
	return acquireStateLockContext(context.Background(), root, name, exclusive)
}

func acquireStateLockContext(ctx context.Context, root *os.Root, name string, exclusive bool) (*os.File, error) {
	// Concurrent first creation through openat can transiently return ENOENT on
	// macOS. Retry only that error, rechecking the directory entry every time.
	// Once an existing inode has been observed, a replacement is never accepted.
	var observed os.FileInfo
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before, err := root.Lstat(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("cannot inspect node-state lock")
		}
		if before != nil && (!before.Mode().IsRegular() || !privatefile.PrivateMode(before, false)) {
			return nil, errors.New("node-state lock must be a private regular file")
		}
		if before != nil {
			if observed != nil && !os.SameFile(observed, before) {
				return nil, errors.New("node-state lock changed while opening")
			}
			observed = before
		} else if observed != nil {
			return nil, errors.New("node-state lock changed while opening")
		}
		file, err := root.OpenFile(name, stateLockFlags(), 0o600)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && attempt < 4 {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			var pathError *os.PathError
			if errors.As(err, &pathError) {
				err = pathError.Err
			}
			return nil, &stateOperationError{message: "cannot open private node-state lock", cause: err}
		}
		opened, statErr := file.Stat()
		current, currentErr := root.Lstat(name)
		if statErr != nil || currentErr != nil || !opened.Mode().IsRegular() || !privatefile.PrivateMode(opened, false) || !os.SameFile(opened, current) || observed != nil && !os.SameFile(observed, opened) {
			file.Close()
			return nil, errors.New("node-state lock changed while opening")
		}
		if err := privatefile.CheckFile(file); err != nil {
			file.Close()
			return nil, err
		}
		if err := lockStateContext(ctx, file, exclusive); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}
	return nil, errors.New("cannot open private node-state lock")
}

type stateOperationError struct {
	message string
	cause   error
}

func (err *stateOperationError) Error() string { return err.message }
func (err *stateOperationError) Unwrap() error { return err.cause }

func publishState(root *os.Root, name string, data []byte, rename func(string, string) error) error {
	return publishStateContext(context.Background(), root, name, data, rename)
}

func publishStateContext(ctx context.Context, root *os.Root, name string, data []byte, rename func(string, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	original, err := stateFileInfo(root, name)
	if err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("cannot create private node-state temporary name")
	}
	temporary := ".nodes-" + hex.EncodeToString(random[:]) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot create private node-state temporary file")
	}
	temporaryInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return errors.New("cannot inspect private node-state temporary file")
	}
	defer func() {
		_ = file.Close()
		if temporary != "" {
			current, err := root.Lstat(temporary)
			if err == nil && os.SameFile(temporaryInfo, current) {
				_ = root.Remove(temporary)
			}
		}
	}()
	if err := privatefile.CheckFile(file); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("cannot write private node-state temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("cannot sync private node state")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close private node state")
	}
	current, err := stateFileInfo(root, name)
	if err != nil {
		return err
	}
	if original == nil && current != nil || original != nil && (current == nil || !os.SameFile(original, current) || original.Size() != current.Size() || !original.ModTime().Equal(current.ModTime())) {
		return errors.New("private node state changed before publication")
	}
	directory, err := root.Stat(".")
	if err != nil || !directory.IsDir() || !privatefile.PrivateMode(directory, false) {
		return errors.New("private node-state directory permissions changed")
	}
	if err := privatefile.CheckRoot(root); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rename(temporary, name); err != nil {
		return errors.New("cannot publish private node state")
	}
	temporary = ""
	return nil
}
