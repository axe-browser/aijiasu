// Package localproxy serves SOCKS5 and HTTP proxy requests through an injected
// dialer. It contains no direct-connect fallback or service credentials.
package localproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultHandshakeTimeout = 10 * time.Second
	MaxHeaderBytes          = 32 << 10
	initialAcceptRetryDelay = 5 * time.Millisecond
	maxAcceptRetryDelay     = time.Second
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Config struct {
	Dialer           Dialer
	Username         string
	Password         []byte
	HandshakeTimeout time.Duration
}

type Server struct {
	dialer       Dialer
	timeout      time.Duration
	authenticate bool
	usernameHash [sha256.Size]byte
	passwordHash [sha256.Size]byte
	ctx          context.Context
	cancel       context.CancelFunc

	mu       sync.Mutex
	listener net.Listener
	served   bool
	closed   bool
	conns    map[*trackedConn]struct{}
	workers  sync.WaitGroup
	dials    sync.WaitGroup
}

func NewServer(config Config) (*Server, error) {
	if config.Dialer == nil {
		return nil, errors.New("proxy dialer is required")
	}
	if config.HandshakeTimeout < 0 {
		return nil, errors.New("proxy handshake timeout must be positive")
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if (config.Username == "") != (len(config.Password) == 0) {
		return nil, errors.New("proxy username and password must be configured together")
	}
	if len(config.Username) > 255 || len(config.Password) > 255 ||
		strings.ContainsAny(config.Username, ":\r\n\x00") {
		return nil, errors.New("proxy credentials are not valid for the supported authentication methods")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		dialer: config.Dialer, timeout: config.HandshakeTimeout,
		authenticate: config.Username != "",
		usernameHash: sha256.Sum256([]byte(config.Username)),
		passwordHash: sha256.Sum256(config.Password),
		ctx:          ctx, cancel: cancel, conns: make(map[*trackedConn]struct{}),
	}, nil
}

// Serve takes ownership of listener and blocks until it is closed or ctx ends.
// A graceful Close or context cancellation returns nil, after all sessions end.
// A Server can serve only once.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return errors.New("proxy context and listener are required")
	}
	server.mu.Lock()
	if server.closed || server.served {
		server.mu.Unlock()
		return errors.New("proxy server is closed or already serving")
	}
	server.served = true
	server.listener = listener
	server.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	defer server.Close()
	var retryDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if server.ctx.Err() != nil || ctx.Err() != nil {
				return nil
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Temporary() {
				if retryDelay == 0 {
					retryDelay = initialAcceptRetryDelay
				} else {
					retryDelay = min(retryDelay*2, maxAcceptRetryDelay)
				}
				timer := time.NewTimer(retryDelay)
				select {
				case <-server.ctx.Done():
					timer.Stop()
					return nil
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
			return errors.New("proxy listener stopped unexpectedly")
		}
		retryDelay = 0
		server.mu.Lock()
		if server.closed || ctx.Err() != nil {
			server.mu.Unlock()
			_ = conn.Close()
			continue
		}
		client := server.trackLocked(conn)
		server.workers.Add(1)
		server.mu.Unlock()
		go func() {
			defer server.workers.Done()
			defer client.Close()
			server.handle(client)
		}()
	}
}

// Close interrupts both pending handshakes and established sessions and waits
// for their handlers. Repeated or concurrent calls are safe.
func (server *Server) Close() error {
	server.mu.Lock()
	server.closed = true
	server.cancel()
	listener := server.listener
	connections := make([]*trackedConn, 0, len(server.conns))
	for conn := range server.conns {
		connections = append(connections, conn)
	}
	server.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	server.workers.Wait()
	server.dials.Wait()
	return nil
}

func (server *Server) Addr() net.Addr {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener == nil {
		return nil
	}
	return server.listener.Addr()
}

func (server *Server) trackLocked(conn net.Conn) *trackedConn {
	tracked := &trackedConn{Conn: conn, server: server}
	server.conns[tracked] = struct{}{}
	return tracked
}

func (server *Server) dial(ctx context.Context, address string) (*trackedConn, error) {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil, errors.New("upstream connection canceled")
	}
	server.dials.Add(1)
	server.mu.Unlock()
	defer server.dials.Done()
	// HTTP Transport can detach dialing from an individual request's context.
	// Server shutdown must still interrupt and join every in-flight dial.
	dialContext, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(server.ctx, cancel)
	defer stop()
	defer cancel()
	conn, err := server.dialer.DialContext(dialContext, "tcp", address)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, errors.New("upstream connection failed")
	}
	if conn == nil {
		return nil, errors.New("upstream connection failed")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed || dialContext.Err() != nil {
		_ = conn.Close()
		return nil, errors.New("upstream connection canceled")
	}
	return server.trackLocked(conn), nil
}

func (server *Server) validCredentials(username, password []byte) bool {
	usernameHash := sha256.Sum256(username)
	passwordHash := sha256.Sum256(password)
	return subtle.ConstantTimeCompare(usernameHash[:], server.usernameHash[:])&
		subtle.ConstantTimeCompare(passwordHash[:], server.passwordHash[:]) == 1
}

func (server *Server) handle(client *trackedConn) {
	deadline := time.Now().Add(server.timeout)
	if err := client.SetDeadline(deadline); err != nil {
		return
	}
	reader := bufio.NewReader(client)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 5 {
		server.serveSOCKS(client, reader, deadline)
		return
	}
	server.serveHTTP(client, reader, deadline)
}

type trackedConn struct {
	net.Conn
	server *Server
	once   sync.Once
	err    error
}

func (conn *trackedConn) Close() error {
	conn.once.Do(func() {
		conn.server.mu.Lock()
		delete(conn.server.conns, conn)
		conn.server.mu.Unlock()
		conn.err = conn.Conn.Close()
	})
	return conn.err
}

// Backends with stream half-close support should implement CloseWrite. A plain
// net.Conn cannot express EOF independently; closing it is the bounded fallback.
func (conn *trackedConn) CloseWrite() error {
	if half, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return conn.Close()
}

func relay(client, upstream *trackedConn, clientReader io.Reader) {
	results := make(chan error, 2)
	copyDirection := func(destination *trackedConn, reader io.Reader) {
		_, err := io.Copy(destination, reader)
		if err == nil {
			err = destination.CloseWrite()
		}
		if err != nil {
			_ = client.Close()
			_ = upstream.Close()
		}
		results <- err
	}
	go copyDirection(upstream, clientReader)
	go copyDirection(client, upstream)
	<-results
	<-results
}
