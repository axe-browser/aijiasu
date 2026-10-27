package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"aijiasu-native/internal/native/privatefile"
)

const maxRPCRequestBytes = 4 << 10
const maxRPCResponseBytes = 256 << 10
const maxRPCConnections = 128

const minRPCAcceptRetry = 5 * time.Millisecond
const maxRPCAcceptRetry = time.Second

type reply struct {
	Status Status `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Call exchanges one bounded JSON request with the private local worker. A stop
// reply is emitted only after transport and private runtime resources are gone.
func Call(ctx context.Context, directory string, request Request) (Status, error) {
	if ctx == nil {
		return Status{}, errors.New("runtime context is required")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, safeFailure("runtime request interrupted", err)
	}
	data, err := json.Marshal(request)
	if err != nil || len(data)+1 > maxRPCRequestBytes || !validCommand(request) {
		return Status{}, errors.New("invalid runtime request")
	}
	operation, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	path, err := runtimeDirectoryPath(directory)
	if err != nil {
		return Status{}, err
	}
	root, _, err := openExistingDirectory(path)
	if err != nil {
		return Status{}, err
	}
	info, statErr := root.Lstat(socketName)
	_ = root.Close()
	if errors.Is(statErr, os.ErrNotExist) {
		return Status{}, ErrNotRunning
	}
	if statErr != nil || info.Mode()&os.ModeSocket == 0 || !privateRuntimeSocketMode(info) || privatefile.CheckPath(filepath.Join(path, socketName)) != nil {
		return Status{}, errors.New("runtime socket must be private and not a symbolic link")
	}
	conn, err := (&net.Dialer{}).DialContext(operation, "unix", filepath.Join(path, socketName))
	if err != nil {
		return Status{}, runtimeDialFailure(operation, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(operation, func() { _ = conn.Close() })
	defer stop()
	if deadline, exists := operation.Deadline(); exists {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeAll(conn, append(data, '\n')); err != nil {
		return Status{}, safeFailure("runtime request interrupted", operation.Err())
	}
	line, err := readLine(conn, maxRPCResponseBytes)
	if err != nil {
		return Status{}, safeFailure("runtime response is unavailable", operation.Err())
	}
	var answer reply
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&answer) != nil || decoder.Decode(new(any)) != io.EOF {
		return Status{}, errors.New("invalid runtime response")
	}
	if answer.Error != "" {
		return answer.Status, errors.New(safeRPCMessage(answer.Error))
	}
	return answer.Status, nil
}

func runtimeDialFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return safeFailure("runtime request interrupted", ctx.Err())
	}
	if errors.Is(err, os.ErrNotExist) || runtimeConnectionRefused(err) {
		return ErrNotRunning
	}
	return safeFailure("cannot connect to runtime control interface", err)
}

func validCommand(request Request) bool {
	switch request.Command {
	case "status", "disconnect", "stop":
		return request.NodeID == ""
	case "connect", "switch":
		return request.NodeID != ""
	default:
		return false
	}
}

type rpcServer struct {
	ctx         context.Context
	listener    net.Listener
	manager     *manager
	cancel      context.CancelFunc
	cleanupDone <-chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]bool
	workers     sync.WaitGroup
	stopping    bool
}

func newRPCServer(ctx context.Context, listener net.Listener, manager *manager, cancel context.CancelFunc, cleanupDone <-chan struct{}) *rpcServer {
	return &rpcServer{ctx: ctx, listener: listener, manager: manager, cancel: cancel, cleanupDone: cleanupDone, connections: make(map[net.Conn]bool)}
}

func (server *rpcServer) serve() error {
	var retry time.Duration
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if server.ctx.Err() != nil {
				return nil
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Temporary() {
				if retry == 0 {
					retry = minRPCAcceptRetry
				} else {
					retry = min(retry*2, maxRPCAcceptRetry)
				}
				timer := time.NewTimer(retry)
				select {
				case <-server.ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
			return errors.New("runtime control listener failed")
		}
		retry = 0
		server.mu.Lock()
		if server.ctx.Err() != nil || len(server.connections) >= maxRPCConnections {
			server.mu.Unlock()
			_ = conn.Close()
			continue
		}
		server.connections[conn] = false
		server.workers.Add(1)
		server.mu.Unlock()
		go server.handle(conn)
	}
}

func (server *rpcServer) stopRequested() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.stopping
}

func (server *rpcServer) closeOrdinaryConnections() {
	server.mu.Lock()
	defer server.mu.Unlock()
	for conn, stopping := range server.connections {
		if !stopping {
			_ = conn.Close()
		}
	}
}

func (server *rpcServer) handle(conn net.Conn) {
	defer server.workers.Done()
	defer func() { _ = conn.Close(); server.mu.Lock(); delete(server.connections, conn); server.mu.Unlock() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(conn, maxRPCRequestBytes)
	if err != nil {
		server.respond(conn, reply{Error: "invalid runtime request"})
		return
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !validCommand(request) {
		server.respond(conn, reply{Error: "invalid runtime request"})
		return
	}
	_ = conn.SetDeadline(time.Now().Add(rpcTimeout))
	if request.Command == "stop" {
		server.mu.Lock()
		server.connections[conn] = true
		server.stopping = true
		server.mu.Unlock()
		server.cancel()
		<-server.cleanupDone
		server.respond(conn, reply{Status: server.manager.status()})
		return
	}
	operation, cancel := context.WithCancel(server.ctx)
	defer cancel()
	// Call closes its connection when canceled. Reading a byte after the single
	// request observes that disconnect and interrupts queued or active switching.
	go func() { var extra [1]byte; _, _ = conn.Read(extra[:]); cancel() }()
	switch request.Command {
	case "connect", "switch":
		err = server.manager.connect(operation, request.NodeID)
	case "disconnect":
		err = server.manager.disconnect(operation)
	}
	answer := reply{Status: server.manager.status()}
	if err != nil {
		answer.Error = safeRPCMessage(err.Error())
	}
	server.respond(conn, answer)
}

func (server *rpcServer) respond(conn net.Conn, answer reply) {
	data, err := json.Marshal(answer)
	if err != nil || len(data)+1 > maxRPCResponseBytes {
		data = []byte(`{"status":{"running":false,"connected":false,"active_connections":0},"error":"runtime response exceeds size limit"}`)
	}
	_ = writeAll(conn, append(data, '\n'))
}

func safeRPCMessage(message string) string {
	switch message {
	case "invalid runtime request", "node connection interrupted", "cannot load cached session", "session account changed; stop and restart required", "authorized node is missing or invalid", "runtime transport metadata is invalid", "cannot initialize node transport", "node authentication failed", "HTTPS exit verification failed", "disconnect interrupted", "runtime response exceeds size limit":
		return message
	default:
		return "runtime request failed"
	}
}

func readLine(reader io.Reader, maximum int) ([]byte, error) {
	buffered := bufio.NewReaderSize(io.LimitReader(reader, int64(maximum)+1), maximum+1)
	line, err := buffered.ReadSlice('\n')
	if err != nil || len(line) > maximum {
		return nil, errors.New("runtime JSON frame is invalid or exceeds size limit")
	}
	return line, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
