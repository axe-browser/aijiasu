package runtime

import (
	"context"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	standardruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/fvproxy"
	"aijiasu-native/internal/native/privatefile"
)

const testPassword = "constructed-runtime-password"

type historyRecord struct {
	directory string
	account   string
	nodeID    string
	at        time.Time
}

type fakeEngine struct {
	mu            sync.Mutex
	closed        bool
	authenticated bool
	auth          func(context.Context) error
}

func (engine *fakeEngine) Authenticate(ctx context.Context) error {
	if engine.auth != nil {
		if err := engine.auth(ctx); err != nil {
			return err
		}
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.authenticated = true
	return nil
}
func (engine *fakeEngine) DialContext(context.Context, string, string) (net.Conn, error) {
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}
func (engine *fakeEngine) Status() fvproxy.Status {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return fvproxy.Status{Authenticated: engine.authenticated && !engine.closed}
}
func (engine *fakeEngine) Close() error {
	engine.mu.Lock()
	engine.closed = true
	engine.mu.Unlock()
	return nil
}
func (engine *fakeEngine) isClosed() bool {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.closed
}

func testConfig(t *testing.T) Config {
	t.Helper()
	directory, err := os.MkdirTemp("", "ajs-rt-")
	if err != nil {
		t.Fatal(err)
	}
	temporary := directory
	t.Cleanup(func() { _ = os.RemoveAll(temporary) })
	if standardruntime.GOOS == "windows" {
		directory = filepath.Join(directory, "p")
		if err := privatefile.MkdirAll(directory); err != nil {
			t.Fatal(err)
		}
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), 1023)
	modulus.Add(modulus, big.NewInt(1))
	config := Config{Directory: directory, Password: []byte(testPassword), ListenAddress: "127.0.0.1:0",
		Session:   clientapi.Session{Username: "test-user", ServiceUsername: "canonical-user", LoginToken: "HTTP-token-only", Nodes: []clientapi.Node{{ID: "a", Host: "a.example.test", TCPPort: 443}, {ID: "b", Host: "b.example.test", TCPPort: 444}}},
		Profile:   clientapi.Profile{CommonParameters: map[string]string{"_site": "ajs", "v": "4.3.0.1", "_m": "linux", "_os_dev": "public-device", "_os_ver": "public-os", "_os_dim": "public-dim", "_uid": "publicUID123"}},
		Transport: authstore.TransportProfile{Version: 1, CoreVersion: "public-version", Modulus: modulus.String(), Exponent: "65537"}}
	if err := authstore.SaveSession(directory, config.Session); err != nil {
		t.Fatal(err)
	}
	return config
}
func testDeps(factory func(fvproxy.Config) (proxyEngine, error)) dependencies {
	return dependencies{newEngine: factory, verify: func(context.Context, proxyEngine, string) (string, error) { return "203.0.113.1", nil }, load: authstore.LoadSession}
}
func await(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("runtime operation timed out")
		return nil
	}
}

func TestManagerSwitchRetainsOldUntilVerifiedAndReloadsNodes(t *testing.T) {
	config := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	var created []*fakeEngine
	var records []historyRecord
	failAuth, failVerify := false, false
	deps := testDeps(func(cfg fvproxy.Config) (proxyEngine, error) {
		real, err := fvproxy.NewEngine(cfg)
		if err != nil {
			t.Fatalf("invalid actual engine configuration: %v", err)
		}
		_ = real.Close()
		fields := cfg.Authentication
		if len(fields) != 13 || fields["u"] != "canonical-user" || fields["p"] != testPassword || fields["cuid"] != "publicUID123" || fields["cv"] != "public-version" || fields["dim"] != "public-dim" {
			t.Fatal("authentication metadata mismatch")
		}
		for _, value := range fields {
			if value == config.Session.LoginToken {
				t.Fatal("control-plane token used in data plane")
			}
		}
		engine := &fakeEngine{}
		if failAuth {
			engine.auth = func(context.Context) error { return errors.New(testPassword) }
		}
		created = append(created, engine)
		return engine, nil
	})
	deps.verify = func(context.Context, proxyEngine, string) (string, error) {
		if failVerify {
			return "", errors.New("private-server-response")
		}
		return "203.0.113.1", nil
	}
	deps.recordUse = func(directory, account, nodeID string, at time.Time) error {
		records = append(records, historyRecord{directory, account, nodeID, at})
		return nil
	}
	manager, err := newManager(ctx, config, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); manager.close() }()
	before := time.Now().UTC()
	if err := manager.connect(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].directory != config.Directory || records[0].account != config.Session.Username || records[0].nodeID != "a" || records[0].at.Location() != time.UTC || records[0].at.Before(before) || records[0].at.After(time.Now().UTC()) {
		t.Fatal("successful connection was not recorded once with its account, node and UTC time")
	}
	old := created[0]
	for _, authentication := range []bool{true, false} {
		failAuth, failVerify = authentication, !authentication
		if err := manager.connect(ctx, "b"); err == nil || strings.Contains(err.Error(), testPassword) || strings.Contains(err.Error(), "private-server-response") {
			t.Fatal("failed candidate succeeded or leaked a value")
		}
		if !created[len(created)-1].isClosed() || old.isClosed() || manager.status().NodeID != "a" {
			t.Fatal("failed switch replaced working engine")
		}
		if len(records) != 1 {
			t.Fatal("failed authentication or exit verification recorded node use")
		}
	}
	failAuth, failVerify = false, false
	refreshed := config.Session
	refreshed.Nodes = []clientapi.Node{{ID: "c", Host: "c.example.test", TCPPort: 445}}
	if err := authstore.SaveSession(config.Directory, refreshed); err != nil {
		t.Fatal(err)
	}
	if err := manager.connect(ctx, "c"); err != nil || !old.isClosed() || manager.status().NodeID != "c" {
		t.Fatalf("same-account cache update failed: %v", err)
	}
	if len(records) != 2 || records[1].nodeID != "c" {
		t.Fatal("successful switch was not recorded once")
	}
	if err := manager.connect(ctx, "c"); err != nil || len(records) != 3 || records[2].nodeID != "c" {
		t.Fatal("explicit successful connection to the same node was not recorded once")
	}
	refreshed.Username = "different-account"
	if err := authstore.SaveSession(config.Directory, refreshed); err != nil {
		t.Fatal(err)
	}
	if err := manager.connect(ctx, "c"); err == nil || err.Error() != "session account changed; stop and restart required" || manager.status().NodeID != "c" {
		t.Fatal("account change was not rejected")
	}
	if len(records) != 3 {
		t.Fatal("rejected account change recorded node use")
	}
	if err := manager.disconnect(ctx); err != nil || !manager.status().Running || manager.status().Connected {
		t.Fatal("disconnect did not leave an idle worker")
	}
	if _, err := manager.DialContext(ctx, "tcp", "example.test:443"); err == nil {
		t.Fatal("disconnected manager fell through to a direct connection")
	}
}

func TestManagerHistoryFailureDoesNotUndoConnection(t *testing.T) {
	config := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var engines []*fakeEngine
	deps := testDeps(func(fvproxy.Config) (proxyEngine, error) {
		engine := &fakeEngine{}
		engines = append(engines, engine)
		return engine, nil
	})
	manager, err := newManager(ctx, config, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.close()
	failWrite := true
	calls := 0
	manager.deps.recordUse = func(directory, account, nodeID string, at time.Time) error {
		calls++
		state := manager.status()
		if !state.Connected || state.NodeID != nodeID {
			t.Fatal("history was saved before the successful atomic connection swap")
		}
		if failWrite {
			return errors.New(testPassword)
		}
		return nil
	}
	if err := manager.connect(ctx, "a"); err != nil {
		t.Fatal("history write failure was reported as connection failure")
	}
	state := manager.status()
	if !state.Connected || state.NodeID != "a" || !state.HistoryWarning || state.LastError != "" || engines[0].isClosed() || calls != 1 {
		t.Fatal("history write failure undid a connection or did not report a safe warning")
	}
	failWrite = false
	if err := manager.connect(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	state = manager.status()
	if !state.Connected || state.NodeID != "b" || state.HistoryWarning || !engines[0].isClosed() || engines[1].isClosed() || calls != 2 {
		t.Fatal("successful history save did not clear the warning and preserve the new connection")
	}
}

func startRuntime(t *testing.T, config Config, deps dependencies) (Status, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan Status, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, config, "a", func(status Status) { ready <- status }, deps) }()
	t.Cleanup(cancel)
	select {
	case status := <-ready:
		return status, cancel, done
	case err := <-done:
		t.Fatalf("runtime startup failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("runtime readiness timed out")
	}
	return Status{}, cancel, done
}

func TestRunCallStopCleansResourcesBeforeReply(t *testing.T) {
	config := testConfig(t)
	var mu sync.Mutex
	var engines []*fakeEngine
	var history []string
	deps := testDeps(func(fvproxy.Config) (proxyEngine, error) {
		engine := &fakeEngine{}
		mu.Lock()
		engines = append(engines, engine)
		mu.Unlock()
		return engine, nil
	})
	deps.recordUse = func(directory, account, nodeID string, at time.Time) error {
		mu.Lock()
		history = append(history, nodeID)
		mu.Unlock()
		return nil
	}
	ready, _, done := startRuntime(t, config, deps)
	if !ready.Connected || !ready.Running {
		t.Fatal("worker reported ready before connection")
	}
	mu.Lock()
	initialRecorded := len(history) == 1 && history[0] == "a"
	mu.Unlock()
	if !initialRecorded {
		t.Fatal("initial runtime connection was not recorded exactly once before readiness")
	}
	for path, mode := range map[string]os.FileMode{config.Directory: 0o700, filepath.Join(config.Directory, socketName): 0o600, filepath.Join(config.Directory, lockName): 0o600} {
		info, err := os.Lstat(path)
		if err != nil || standardruntime.GOOS != "windows" && info.Mode().Perm() != mode || privatefile.CheckPath(path) != nil {
			t.Fatal("runtime resources are not private")
		}
	}
	second := config
	second.Password = []byte(testPassword)
	if err := run(context.Background(), second, "", nil, deps); err == nil {
		t.Fatal("singleton admitted another instance")
	}
	for _, raw := range []string{strings.Repeat("x", maxRPCRequestBytes+1) + "\n", `{"command":"status","password":"private-value"}` + "\n"} {
		conn, err := net.Dial("unix", filepath.Join(config.Directory, socketName))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(conn, raw)
		data, _ := readLine(conn, maxRPCResponseBytes)
		_ = conn.Close()
		if !strings.Contains(string(data), "invalid runtime request") || strings.Contains(string(data), "private-value") {
			t.Fatal("RPC limit/schema check leaked or failed")
		}
	}
	status, err := Call(context.Background(), config.Directory, Request{Command: "disconnect"})
	if err != nil || !status.Running || status.Connected {
		t.Fatalf("disconnect RPC failed: %v", err)
	}
	status, err = Call(context.Background(), config.Directory, Request{Command: "switch", NodeID: "b"})
	if err != nil || !status.Connected || status.NodeID != "b" {
		t.Fatalf("switch RPC failed: %v", err)
	}
	mu.Lock()
	switchRecorded := len(history) == 2 && history[1] == "b"
	mu.Unlock()
	if !switchRecorded {
		t.Fatal("RPC switch was not recorded exactly once, or disconnect recorded use")
	}
	status, err = Call(context.Background(), config.Directory, Request{Command: "stop"})
	if err != nil || status.Running || status.Connected {
		t.Fatalf("stop RPC failed: %v", err)
	}
	for _, value := range config.Password {
		if value != 0 {
			t.Fatal("stop replied before clearing password")
		}
	}
	if _, err := os.Lstat(filepath.Join(config.Directory, socketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stop replied before removing socket")
	}
	if conn, err := net.DialTimeout("tcp", ready.ListenAddress, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("stop retained listener")
	}
	directory, err := openRuntimeDirectory(config.Directory)
	if err != nil {
		t.Fatalf("stop retained singleton lock: %v", err)
	}
	directory.close()
	mu.Lock()
	for _, engine := range engines {
		if !engine.isClosed() {
			t.Error("stop retained engine")
		}
	}
	mu.Unlock()
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if _, err := Call(context.Background(), config.Directory, Request{Command: "status"}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("missing runtime classification: %v", err)
	}
}

func TestCancelSwitchAndForegroundCleanup(t *testing.T) {
	config := testConfig(t)
	entered := make(chan struct{})
	candidate := &fakeEngine{auth: func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }}
	deps := testDeps(func(cfg fvproxy.Config) (proxyEngine, error) {
		if strings.HasPrefix(cfg.Address, "b.") {
			return candidate, nil
		}
		return &fakeEngine{}, nil
	})
	_, cancelRun, done := startRuntime(t, config, deps)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := Call(ctx, config.Directory, Request{Command: "switch", NodeID: "b"}); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("switch did not start")
	}
	cancel()
	if err := await(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost cause: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for !candidate.isClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !candidate.isClosed() {
		t.Fatal("canceled candidate remained open")
	}
	status, err := Call(context.Background(), config.Directory, Request{Command: "status"})
	if err != nil || !status.Connected || status.NodeID != "a" {
		t.Fatal("canceled switch lost original engine")
	}
	conn, err := net.Dial("unix", filepath.Join(config.Directory, socketName))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancelRun()
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestInitialCancellationAndSocketRefusesOtherFiles(t *testing.T) {
	config := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	var ready atomic.Bool
	candidate := &fakeEngine{auth: func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }}
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, config, "a", func(Status) { ready.Store(true) }, testDeps(func(fvproxy.Config) (proxyEngine, error) { return candidate, nil }))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial authentication did not start")
	}
	cancel()
	if err := await(t, done); err == nil || ready.Load() || !candidate.isClosed() {
		t.Fatal("initial cancellation did not close candidate before readiness")
	}
	if _, err := os.Lstat(filepath.Join(config.Directory, socketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed startup retained socket")
	}
	for _, symbolic := range []bool{false, true} {
		config := testConfig(t)
		path := filepath.Join(config.Directory, socketName)
		if symbolic {
			if err := os.Symlink("session.json", path); err != nil {
				t.Skip("symbolic links unavailable")
			}
		} else if err := os.WriteFile(path, []byte("must-remain"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(context.Background(), config, "", nil, testDeps(func(fvproxy.Config) (proxyEngine, error) { return &fakeEngine{}, nil })); err == nil {
			t.Fatal("runtime overwrote unrelated socket-path file")
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("runtime removed rejected socket-path file")
		}
	}
}

func TestQueuedSwitchCancellationDoesNotTouchWorkingEngine(t *testing.T) {
	config := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	candidate := &fakeEngine{auth: func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }}
	var creations atomic.Int32
	deps := testDeps(func(cfg fvproxy.Config) (proxyEngine, error) {
		creations.Add(1)
		if strings.HasPrefix(cfg.Address, "b.") {
			return candidate, nil
		}
		return &fakeEngine{}, nil
	})
	manager, err := newManager(ctx, config, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); manager.close() }()
	if err := manager.connect(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	active, cancelActive := context.WithCancel(ctx)
	activeDone := make(chan error, 1)
	go func() { activeDone <- manager.connect(active, "b") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("active switch did not acquire operation gate")
	}
	queued, cancelQueued := context.WithCancel(ctx)
	queuedDone := make(chan error, 1)
	go func() { queuedDone <- manager.connect(queued, "a") }()
	cancelQueued()
	if err := await(t, queuedDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation lost cause: %v", err)
	}
	if creations.Load() != 2 || manager.status().NodeID != "a" || !manager.status().Connected {
		t.Fatal("queued cancellation touched active candidate or working engine")
	}
	cancelActive()
	if err := await(t, activeDone); err == nil || !candidate.isClosed() {
		t.Fatal("active canceled candidate was retained")
	}
}
