package runtime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/fvproxy"
	"aijiasu-native/internal/native/nodemgr"
)

type proxyEngine interface {
	Authenticate(context.Context) error
	DialContext(context.Context, string, string) (net.Conn, error)
	Status() fvproxy.Status
	Close() error
}

type dependencies struct {
	newEngine func(fvproxy.Config) (proxyEngine, error)
	verify    func(context.Context, proxyEngine, string) (string, error)
	load      func(string) (clientapi.Session, error)
	recordUse func(string, string, string, time.Time) error
}

func productionDependencies() dependencies {
	return dependencies{
		newEngine: func(config fvproxy.Config) (proxyEngine, error) { return fvproxy.NewEngine(config) },
		verify:    verifyExitIP, load: authstore.LoadSession, recordUse: nodemgr.RecordUse,
	}
}

type manager struct {
	mu             sync.RWMutex
	gate           chan struct{}
	ctx            context.Context
	config         Config
	deps           dependencies
	current        proxyEngine
	node           clientapi.Node
	exitIP         string
	listen         string
	lastError      string
	running        bool
	historyWarning bool
}

func newManager(ctx context.Context, config Config, deps dependencies) (*manager, error) {
	if strings.TrimSpace(config.Session.Username) == "" || config.Session.ServiceUsername == "" || len(config.Session.ServiceUsername) > 64<<10 || len(config.Password) == 0 || len(config.Password) > 4<<10 {
		return nil, errors.New("runtime requires a canonical service username and an in-memory password")
	}
	for _, key := range []string{"_site", "v", "_m", "_os_dev", "_os_ver", "_os_dim", "_uid"} {
		if _, exists := config.Profile.CommonParameters[key]; !exists {
			return nil, errors.New("runtime protocol metadata is incomplete")
		}
	}
	if config.Profile.CommonParameters["_os_dim"] == "" || config.Transport.Version != 1 || config.Transport.CoreVersion == "" {
		return nil, errors.New("runtime requires device metadata and a transport profile")
	}
	if _, err := config.Transport.PublicKey(); err != nil {
		return nil, errors.New("runtime transport public key is invalid")
	}
	// Own the password buffer and mutable metadata without retaining token data
	// that is unused by the data plane. The caller retains ownership of its input.
	config.Password = append([]byte(nil), config.Password...)
	config.Session.Nodes = append([]clientapi.Node(nil), config.Session.Nodes...)
	config.Session.LoginToken, config.Session.SyncVersion = "", nil
	parameters := make(map[string]string, len(config.Profile.CommonParameters))
	for key, value := range config.Profile.CommonParameters {
		parameters[key] = value
	}
	config.Profile.CommonParameters = parameters
	config.Profile.SigningSeed = ""
	return &manager{ctx: ctx, config: config, deps: deps, gate: make(chan struct{}, 1), running: true}, nil
}

func (manager *manager) acquire(ctx context.Context) error {
	select {
	case manager.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-manager.gate
			return err
		}
		if err := manager.ctx.Err(); err != nil {
			<-manager.gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-manager.ctx.Done():
		return manager.ctx.Err()
	}
}

func (manager *manager) connect(ctx context.Context, nodeID string) error {
	if err := manager.acquire(ctx); err != nil {
		return safeFailure("node connection interrupted", err)
	}
	defer func() { <-manager.gate }()
	return manager.connectNode(ctx, nodeID)
}

// connectNode requires the operation gate, including the reserved startup slot.
func (manager *manager) connectNode(ctx context.Context, nodeID string) error {
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(manager.ctx, cancel)
	defer stop()
	defer cancel()
	latest, err := manager.deps.load(manager.config.Directory)
	if err != nil {
		return manager.failed("cannot load cached session", err)
	}
	if latest.Username != manager.config.Session.Username || latest.ServiceUsername != manager.config.Session.ServiceUsername {
		return manager.failed("session account changed; stop and restart required", nil)
	}
	manager.config.Session.Nodes = append([]clientapi.Node(nil), latest.Nodes...)
	var selected clientapi.Node
	found := false
	for _, node := range manager.config.Session.Nodes {
		if node.ID == nodeID && nodeID != "" {
			selected, found = node, true
			break
		}
	}
	if !found || !validNodeAddress(selected) {
		return manager.failed("authorized node is missing or invalid", nil)
	}
	publicKey, err := manager.config.Transport.PublicKey()
	if err != nil {
		return manager.failed("runtime transport metadata is invalid", err)
	}
	parameters := manager.config.Profile.CommonParameters
	engine, err := manager.deps.newEngine(fvproxy.Config{
		Address: net.JoinHostPort(selected.Host, strconv.Itoa(selected.TCPPort)), PublicKey: publicKey,
		Authentication: map[string]string{
			"u": manager.config.Session.ServiceUsername, "p": string(manager.config.Password), "cuid": parameters["_uid"], "cseid": "",
			"st": parameters["_site"], "v": parameters["v"], "cv": manager.config.Transport.CoreVersion,
			"osp": parameters["_m"], "osd": parameters["_os_dev"], "osv": parameters["_os_ver"], "dim": parameters["_os_dim"], "peip": "", "ce": "",
		},
	})
	if err != nil {
		return manager.failed("cannot initialize node transport", err)
	}
	if engine == nil {
		return manager.failed("cannot initialize node transport", nil)
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = engine.Close()
		}
	}()
	if err := engine.Authenticate(operation); err != nil {
		return manager.failed("node authentication failed", err)
	}
	exitIP, err := manager.deps.verify(operation, engine, manager.config.VerifyURL)
	if err != nil || net.ParseIP(exitIP) == nil {
		return manager.failed("HTTPS exit verification failed", err)
	}
	if err := operation.Err(); err != nil {
		return manager.failed("node connection interrupted", err)
	}
	manager.mu.Lock()
	old := manager.current
	manager.current, manager.node, manager.exitIP, manager.lastError = engine, selected, exitIP, ""
	manager.mu.Unlock()
	accepted = true
	if old != nil {
		_ = old.Close()
	}
	if manager.deps.recordUse != nil {
		err := manager.deps.recordUse(manager.config.Directory, manager.config.Session.Username, selected.ID, time.Now().UTC())
		manager.mu.Lock()
		manager.historyWarning = err != nil
		manager.mu.Unlock()
	}
	return nil
}

func validNodeAddress(node clientapi.Node) bool {
	if node.TCPPort < 1 || node.TCPPort > 65535 || node.Host == "" || strings.TrimSpace(node.Host) != node.Host || strings.ContainsAny(node.Host, "/\\@?#\r\n\x00") {
		return false
	}
	return !strings.Contains(node.Host, ":") || net.ParseIP(node.Host) != nil
}

func (manager *manager) failed(message string, cause error) error {
	manager.mu.Lock()
	manager.lastError = message
	manager.mu.Unlock()
	return safeFailure(message, cause)
}

func (manager *manager) disconnect(ctx context.Context) error {
	if err := manager.acquire(ctx); err != nil {
		return safeFailure("disconnect interrupted", err)
	}
	defer func() { <-manager.gate }()
	manager.mu.Lock()
	old := manager.current
	manager.current, manager.node, manager.exitIP, manager.lastError = nil, clientapi.Node{}, "", ""
	manager.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (manager *manager) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	manager.mu.RLock()
	current := manager.current
	manager.mu.RUnlock()
	if current == nil {
		return nil, errors.New("runtime is disconnected")
	}
	conn, err := current.DialContext(ctx, network, address)
	if err != nil {
		return nil, safeFailure("proxy stream could not be opened", err)
	}
	return conn, nil
}

func (manager *manager) status() Status {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	status := Status{Running: manager.running, NodeID: manager.node.ID, NodeTitle: manager.node.Title, ListenAddress: manager.listen, ExitIP: manager.exitIP, LastError: manager.lastError, HistoryWarning: manager.historyWarning}
	if manager.current != nil {
		engine := manager.current.Status()
		status.Connected, status.ActiveConnections = engine.Authenticated, engine.ActiveConnections
		if !engine.Authenticated && status.LastError == "" {
			status.LastError = "proxy session is not authenticated"
		}
	}
	return status
}

func (manager *manager) close() {
	manager.gate <- struct{}{}
	defer func() { <-manager.gate }()
	manager.mu.Lock()
	old := manager.current
	manager.current, manager.running, manager.node, manager.exitIP = nil, false, clientapi.Node{}, ""
	manager.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	clear(manager.config.Password)
	manager.config.Password = nil
}

type operationError struct {
	message string
	cause   error
}

func (err *operationError) Error() string { return err.message }
func (err *operationError) Unwrap() error { return err.cause }
func safeFailure(message string, cause error) error {
	return &operationError{message: message, cause: cause}
}
