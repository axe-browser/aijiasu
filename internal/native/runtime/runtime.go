// Package runtime hosts the independent foreground proxy and private local RPC.
package runtime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/localproxy"
)

var ErrNotRunning = errors.New("native runtime is not running")

type Config struct {
	Directory     string
	Session       clientapi.Session
	Profile       clientapi.Profile
	Transport     authstore.TransportProfile
	Password      []byte
	ListenAddress string
	VerifyURL     string
}

type Status struct {
	Running           bool   `json:"running"`
	Connected         bool   `json:"connected"`
	NodeID            string `json:"node_id,omitempty"`
	NodeTitle         string `json:"node_title,omitempty"`
	ListenAddress     string `json:"listen_address,omitempty"`
	ExitIP            string `json:"exit_ip,omitempty"`
	ActiveConnections int    `json:"active_connections"`
	LastError         string `json:"last_error,omitempty"`
	HistoryWarning    bool   `json:"history_warning,omitempty"`
}

type Request struct {
	Command string `json:"command"`
	NodeID  string `json:"node_id,omitempty"`
}

// Run blocks until stop or cancellation. An empty initial node starts an idle
// worker; otherwise readiness follows authenticated, HTTPS-verified connection.
// Run takes ownership of Password and clears its bytes before shutdown replies.
func Run(ctx context.Context, config Config, initialNodeID string, onReady func(Status)) error {
	return run(ctx, config, initialNodeID, onReady, productionDependencies())
}

func run(ctx context.Context, config Config, initialNodeID string, onReady func(Status), deps dependencies) (result error) {
	defer clear(config.Password)
	if ctx == nil {
		return errors.New("runtime context is required")
	}
	if err := ctx.Err(); err != nil {
		return safeFailure("runtime interrupted", err)
	}
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:1080"
	}
	if !validListenAddress(config.ListenAddress) {
		return errors.New("proxy listen address must be a literal loopback address and port")
	}
	if config.VerifyURL == "" {
		config.VerifyURL = defaultVerifyURL
	}
	if err := validateVerifyURL(config.VerifyURL); err != nil {
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	releaseLifecycle, err := authstore.LockSessionLifecycleContext(runContext, config.Directory)
	if err != nil {
		return safeFailure("cannot lock login session lifecycle", err)
	}
	defer releaseLifecycle()
	if err := runContext.Err(); err != nil {
		return safeFailure("runtime interrupted", err)
	}
	latest, err := deps.load(config.Directory)
	if err != nil {
		return safeFailure("cannot load cached session", err)
	}
	if latest.Username != config.Session.Username || latest.ServiceUsername != config.Session.ServiceUsername {
		return errors.New("session account changed; stop and restart required")
	}
	directory, err := openRuntimeDirectory(config.Directory)
	if err != nil {
		return err
	}
	config.Directory = directory.path
	closedDirectory := false
	defer func() {
		if !closedDirectory {
			directory.close()
		}
	}()
	manager, err := newManager(runContext, config, deps)
	if err != nil {
		return err
	}
	closedManager := false
	defer func() {
		if !closedManager {
			cancel()
			manager.close()
		}
	}()
	listener, err := directory.bindSocket()
	if err != nil {
		return err
	}
	proxyListener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return errors.New("cannot bind loopback proxy listener")
	}
	defer proxyListener.Close()
	manager.listen = proxyListener.Addr().String()
	proxy, err := localproxy.NewServer(localproxy.Config{Dialer: manager})
	if err != nil {
		return errors.New("cannot initialize local proxy")
	}
	defer proxy.Close()
	if initialNodeID != "" {
		// Reserve the first operation before accepting RPC mutations. Status and
		// stop remain independent of this gate while other mutations queue.
		if err := manager.acquire(runContext); err != nil {
			return safeFailure("runtime interrupted", err)
		}
	}
	cleanupDone := make(chan struct{})
	rpc := newRPCServer(runContext, listener, manager, cancel, cleanupDone)
	rpcDone := make(chan error, 1)
	go func() {
		err := rpc.serve()
		rpcDone <- err
		if err != nil {
			cancel()
		}
	}()
	var proxyDone chan error
	var proxyExited, rpcExited bool
	defer func() {
		cancel()
		_ = listener.Close()
		if !rpcExited {
			if err := <-rpcDone; err != nil && result == nil && ctx.Err() == nil && !rpc.stopRequested() {
				result = errors.New("runtime listener stopped unexpectedly")
			}
		}
		rpc.closeOrdinaryConnections()
		_ = proxy.Close()
		_ = proxyListener.Close()
		if proxyDone != nil && !proxyExited {
			if err := <-proxyDone; err != nil && result == nil && ctx.Err() == nil && !rpc.stopRequested() {
				result = errors.New("runtime listener stopped unexpectedly")
			}
		}
		manager.close()
		closedManager = true
		clear(config.Password)
		directory.close()
		closedDirectory = true
		// All stop replies, including startup cancellation, follow complete cleanup.
		close(cleanupDone)
		rpc.workers.Wait()
	}()
	// Logout holds the same lifecycle lock while stopping and removing the
	// session. Release only once this worker is reachable, before network work.
	releaseLifecycle()
	if initialNodeID != "" {
		err := func() error {
			defer func() { <-manager.gate }()
			err := manager.connectNode(runContext, initialNodeID)
			if err != nil {
				cancel()
			}
			return err
		}()
		if err != nil {
			if rpc.stopRequested() && ctx.Err() == nil {
				// An explicit stop ends this command instead of retrying --best.
				return nil
			}
			return err
		}
	}
	if err := runContext.Err(); err != nil {
		if ctx.Err() != nil {
			return safeFailure("runtime interrupted", ctx.Err())
		}
		if rpc.stopRequested() {
			return nil
		}
		return errors.New("runtime listener stopped unexpectedly")
	}
	proxyDone = make(chan error, 1)
	go func() { proxyDone <- proxy.Serve(runContext, proxyListener) }()
	if onReady != nil && runContext.Err() == nil {
		onReady(manager.status())
	}
	var serveErr error
	select {
	case <-runContext.Done():
	case serveErr = <-rpcDone:
		rpcExited = true
	case serveErr = <-proxyDone:
		proxyExited = true
	}
	if serveErr != nil && ctx.Err() == nil && !rpc.stopRequested() {
		return errors.New("runtime listener stopped unexpectedly")
	}
	return nil
}

func validListenAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	_, portErr := strconv.ParseUint(port, 10, 16)
	return err == nil && ip != nil && ip.IsLoopback() && portErr == nil
}

const rpcTimeout = 45 * time.Second
