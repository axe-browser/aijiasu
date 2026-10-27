package fvproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultProxyTimeout   = 15 * time.Second
	maxEngineConnections  = 256
	maxControlConnections = 1
	keepalivePollInterval = time.Second
	v2PaddingLengthRange  = 200
	controlPaddingTarget  = 1360
)

var (
	ErrEngineClosed      = errors.New("proxy engine is closed")
	ErrNotAuthenticated  = errors.New("proxy engine is not authenticated")
	ErrProxyAuthRejected = errors.New("proxy authentication rejected")
	ErrProxyProtocol     = errors.New("invalid proxy protocol response")
	ErrConnectionLimit   = errors.New("proxy connection limit reached")
)

type connectionKind uint8

const (
	dataConnection connectionKind = iota
	controlConnection
	connectionKindCount
)

type Config struct {
	Address        string
	PublicKey      *rsa.PublicKey
	Authentication map[string]string
	DialContext    func(context.Context, string, string) (net.Conn, error)
	Random         io.Reader
	Timeout        time.Duration
}

type Status struct {
	Authenticated     bool
	ActiveConnections int
	LastError         string
}

type Engine struct {
	mu               sync.Mutex
	authGate         chan struct{}
	randomMu         sync.Mutex
	address          string
	publicKey        rsa.PublicKey
	authentication   map[string]string
	dial             func(context.Context, string, string) (net.Conn, error)
	random           io.Reader
	timeout          time.Duration
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	closed           bool
	authenticated    bool
	keepaliveStarted bool
	generation       uint64
	key              [16]byte
	sid              string
	ka, kat          time.Duration
	kapf             int
	lastAlive        time.Time
	lastError        string
	pending          map[net.Conn]connectionKind
	connections      map[*streamConn]struct{}
	dialing          [connectionKindCount]int
}

// NewEngine validates and copies configuration without dialing or generating a
// session key. This implementation supports the statically recovered TCP v2 path.
func NewEngine(config Config) (*Engine, error) {
	host, port, err := net.SplitHostPort(config.Address)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\x00") || portErr != nil || portNumber == 0 {
		return nil, errors.New("proxy node address must include a host and port")
	}
	if config.PublicKey == nil || config.PublicKey.N == nil || config.PublicKey.N.Sign() <= 0 || config.PublicKey.N.BitLen() != 1024 || config.PublicKey.E < 3 || config.PublicKey.E > 1<<31-1 || config.PublicKey.E%2 == 0 {
		return nil, errors.New("proxy requires a 1024-bit RSA public key with a valid exponent")
	}
	authentication := make(map[string]string, len(config.Authentication))
	for key, value := range config.Authentication {
		if key == "c" || key == "t" {
			return nil, errors.New("proxy command and timestamp are managed by the engine")
		}
		authentication[key] = value
	}
	for _, field := range []string{"u", "p", "cuid", "cseid", "st", "v", "cv", "osp", "osd", "osv", "dim", "peip", "ce"} {
		if _, exists := authentication[field]; !exists {
			return nil, errors.New("proxy authentication metadata is incomplete")
		}
	}
	if authentication["u"] == "" || authentication["p"] == "" || authentication["dim"] == "" {
		return nil, errors.New("proxy credentials and device metadata are required")
	}
	if _, err := encodeFields(authentication); err != nil {
		return nil, errors.New("invalid proxy authentication metadata")
	}
	dial := config.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultProxyTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		address: config.Address, publicKey: rsa.PublicKey{N: new(big.Int).Set(config.PublicKey.N), E: config.PublicKey.E},
		authentication: authentication, dial: dial, random: random, timeout: timeout,
		ctx: ctx, cancel: cancel, ka: 8 * time.Second, kat: 40 * time.Second, kapf: 1,
		pending: make(map[net.Conn]connectionKind), connections: make(map[*streamConn]struct{}),
		authGate: make(chan struct{}, 1),
	}, nil
}

func (engine *Engine) Authenticate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return safeError(ctx, "proxy authentication interrupted", err)
	}
	select {
	case engine.authGate <- struct{}{}:
		defer func() { <-engine.authGate }()
	case <-ctx.Done():
		return safeError(ctx, "proxy authentication interrupted", ctx.Err())
	case <-engine.ctx.Done():
		return ErrEngineClosed
	}
	engine.mu.Lock()
	if engine.closed || engine.authenticated {
		closed := engine.closed
		engine.mu.Unlock()
		if closed {
			return ErrEngineClosed
		}
		return nil
	}
	fields := make(map[string]string, len(engine.authentication)+2)
	for key, value := range engine.authentication {
		fields[key] = value
	}
	engine.mu.Unlock()
	defer clear(fields)
	var key [16]byte
	defer clear(key[:])
	if err := engine.randomBytes(key[:]); err != nil {
		return engine.recordError(safeError(ctx, "proxy random generation failed", err))
	}
	// RSA-OAEP SHA1, empty label: enum 5 is looked up after subtracting 3
	// at 0x1000e3d90 and selects the SHA1 descriptor at 0x100147c30. The
	// 132-byte OAEP prefix/envelope is at 0x100066daa..0x100066dfe.
	engine.randomMu.Lock()
	wrapped, err := rsa.EncryptOAEP(sha1.New(), engine.random, &engine.publicKey, key[:], nil)
	engine.randomMu.Unlock()
	if err != nil {
		return engine.recordError(safeError(ctx, "proxy session key preparation failed", err))
	}
	keyEnvelope := append([]byte("OAEP"), wrapped...)
	fields["c"] = "au"
	fields["t"] = strconv.FormatInt(time.Now().Unix(), 10)
	reply, err := engine.control(ctx, key, base64.StdEncoding.EncodeToString(keyEnvelope), fields)
	if err != nil {
		return engine.recordError(err)
	}
	result, exists := reply["r"]
	if reply["c"] != "aur" || !exists || result == "" {
		return engine.recordError(ErrProxyProtocol)
	}
	if result != "ok" {
		return engine.recordError(ErrProxyAuthRejected)
	}
	sid := reply["sid"]
	if sid == "" || strings.ContainsAny(sid, "\r\n\x00") {
		return engine.recordError(ErrProxyProtocol)
	}
	ka, kat, kapf := keepaliveParameters(reply)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.closed {
		return ErrEngineClosed
	}
	engine.key, engine.sid = key, sid
	engine.ka, engine.kat, engine.kapf = ka, kat, kapf
	engine.authenticated, engine.lastAlive, engine.lastError = true, time.Now(), ""
	engine.generation++
	if !engine.keepaliveStarted {
		engine.keepaliveStarted = true
		engine.wg.Add(1)
		go engine.keepalive()
	}
	return nil
}

func (engine *Engine) control(ctx context.Context, key [16]byte, keyText string, fields map[string]string) (map[string]string, error) {
	body, err := encodeFields(fields)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	paddedBody, err := engine.paddedControlBody(body)
	if err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	// append may allocate a second plaintext buffer; clear both owners.
	defer clear(paddedBody)
	var nonce, outerKey [16]byte
	if err := engine.randomBytes(nonce[:]); err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	if err := engine.randomBytes(outerKey[:]); err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	encrypted := encryptBody(key, nonce, paddedBody)
	payload := []byte("s=\nn=" + hex.EncodeToString(nonce[:]) + "\nk=" + keyText + "\nl=" + strconv.Itoa(len(encrypted)) + "\n")
	payload, err = engine.paddedV2Payload(payload)
	if err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	frame, err := EncodeControlRequest(outerKey, payload, encrypted)
	if err != nil {
		return nil, safeError(ctx, "proxy request preparation failed", err)
	}
	ctx, cancel := context.WithTimeout(ctx, engine.timeout)
	defer cancel()
	conn, stop, err := engine.openPending(ctx, controlConnection)
	if err != nil {
		return nil, safeError(ctx, "proxy control connection failed", err)
	}
	defer func() { stop(); engine.removePending(conn); conn.Close() }()
	if err := writeAll(conn, frame); err != nil {
		return nil, safeError(ctx, "proxy control request failed", err)
	}
	if err := readOuterReply(conn, outerKey); err != nil {
		return nil, safeError(ctx, "proxy control handshake failed", err)
	}
	encryptedReply, err := io.ReadAll(io.LimitReader(conn, maxControlBodyBytes+1))
	if err != nil {
		return nil, safeError(ctx, "proxy control response failed", err)
	}
	if len(encryptedReply) > maxControlBodyBytes {
		return nil, ErrProxyProtocol
	}
	reply, err := decodeFields(encryptBody(key, nonce, encryptedReply))
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (engine *Engine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, safeError(ctx, "proxy TCP connection interrupted", err)
	}
	request, err := connectRequest(network, address)
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	if engine.closed || !engine.authenticated {
		closed := engine.closed
		engine.mu.Unlock()
		if closed {
			return nil, ErrEngineClosed
		}
		return nil, ErrNotAuthenticated
	}
	key, sid, generation := engine.key, engine.sid, engine.generation
	engine.mu.Unlock()
	var nonce, outerKey [16]byte
	if err := engine.randomBytes(nonce[:]); err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	if err := engine.randomBytes(outerKey[:]); err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	payload, err := engine.paddedV2Payload([]byte("s=" + sid + "\nn=" + hex.EncodeToString(nonce[:]) + "\nk=\n"))
	if err != nil {
		return nil, safeError(ctx, "proxy random generation failed", err)
	}
	frame, err := EncodeControlRequest(outerKey, payload, nil)
	if err != nil {
		return nil, ErrProxyProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, engine.timeout)
	defer cancel()
	raw, stop, err := engine.openPending(ctx, dataConnection)
	if err != nil {
		return nil, safeError(ctx, "proxy TCP connection failed", err)
	}
	success := false
	defer func() {
		stop()
		if !success {
			engine.removePending(raw)
			raw.Close()
		}
	}()
	connection := &streamConn{Conn: raw, engine: engine, rx: newStream(key, nonce), tx: newStream(key, nonce)}
	if err = writeAll(raw, frame); err == nil {
		connection.tx.XORKeyStream(request, request)
		err = writeAll(raw, request)
	}
	if err == nil {
		err = readOuterReply(raw, outerKey)
	}
	if err == nil {
		err = readConnectReply(raw, connection.rx)
	}
	if err != nil {
		return nil, engine.recordError(safeError(ctx, "proxy TCP handshake failed", err))
	}
	if !stop() || ctx.Err() != nil {
		return nil, safeError(ctx, "proxy TCP handshake interrupted", ctx.Err())
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, safeError(ctx, "proxy TCP deadline reset failed", err)
	}
	engine.mu.Lock()
	if engine.closed || !engine.authenticated || engine.generation != generation {
		engine.mu.Unlock()
		return nil, ErrNotAuthenticated
	}
	delete(engine.pending, raw)
	engine.connections[connection] = struct{}{}
	engine.lastAlive = time.Now()
	engine.mu.Unlock()
	success = true
	return connection, nil
}

func (engine *Engine) Status() Status {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return Status{Authenticated: engine.authenticated, ActiveConnections: len(engine.connections), LastError: engine.lastError}
}

func (engine *Engine) Close() error {
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		return nil
	}
	engine.closed, engine.authenticated = true, false
	engine.cancel()
	clear(engine.authentication)
	engine.authentication = nil
	clear(engine.key[:])
	engine.sid = ""
	pending := make([]net.Conn, 0, len(engine.pending))
	for conn := range engine.pending {
		pending = append(pending, conn)
	}
	connections := make([]*streamConn, 0, len(engine.connections))
	for conn := range engine.connections {
		connections = append(connections, conn)
	}
	engine.mu.Unlock()
	for _, conn := range pending {
		conn.Close()
	}
	for _, conn := range connections {
		conn.Close()
	}
	engine.wg.Wait()
	return nil
}

func (engine *Engine) randomBytes(data []byte) error {
	engine.randomMu.Lock()
	defer engine.randomMu.Unlock()
	_, err := io.ReadFull(engine.random, data)
	return err
}

// The v2 writer at 0x100085e1e..0x100086118 appends an unterminated
// _= field with 0..199 random lowercase bytes. It is part of the outer
// payload only; the separately encrypted body's length is unchanged.
func (engine *Engine) paddedV2Payload(payload []byte) ([]byte, error) {
	var length [1]byte
	if err := engine.randomBytes(length[:]); err != nil {
		return nil, err
	}
	padding := make([]byte, int(length[0])%v2PaddingLengthRange)
	if err := engine.randomBytes(padding); err != nil {
		clear(padding)
		return nil, err
	}
	for index, value := range padding {
		padding[index] = 'a' + value%26
	}
	payload = append(payload, '_', '=')
	return append(payload, padding...), nil
}

// The control-map serializer at 0x454f13..0x455064 (Linux) and
// 0x100082bc8..0x100082c44 (macOS) adds a second padding field inside
// the session cipher. This is unrelated to the UDP-only binary control head.
func (engine *Engine) paddedControlBody(body []byte) ([]byte, error) {
	available := controlPaddingTarget - len(body)
	if available <= 2 {
		return body, nil
	}
	var length [4]byte
	if err := engine.randomBytes(length[:]); err != nil {
		return nil, err
	}
	padding := make([]byte, int(binary.BigEndian.Uint32(length[:])%uint32(available-2)))
	if err := engine.randomBytes(padding); err != nil {
		clear(padding)
		return nil, err
	}
	for index, value := range padding {
		padding[index] = 'a' + value%26
	}
	body = append(body, '_', '=')
	return append(body, padding...), nil
}

func (engine *Engine) openPending(ctx context.Context, kind connectionKind) (net.Conn, func() bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		return nil, nil, ErrEngineClosed
	}
	if engine.connectionLimitReached(kind) {
		engine.mu.Unlock()
		return nil, nil, ErrConnectionLimit
	}
	engine.dialing[kind]++
	engine.mu.Unlock()
	dialContext, cancelDial := context.WithCancel(ctx)
	stopEngine := context.AfterFunc(engine.ctx, cancelDial)
	conn, err := engine.dial(dialContext, "tcp", engine.address)
	if conn == nil && err == nil {
		err = errors.New("proxy dial returned no connection")
	}
	stopEngine()
	cancelDial()
	engine.mu.Lock()
	engine.dialing[kind]--
	if err != nil {
		engine.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		return nil, nil, err
	}
	if engine.closed || engine.connectionLimitReached(kind) {
		closed := engine.closed
		engine.mu.Unlock()
		conn.Close()
		if closed {
			return nil, nil, ErrEngineClosed
		}
		return nil, nil, ErrConnectionLimit
	}
	engine.pending[conn] = kind
	engine.mu.Unlock()
	if deadline, exists := ctx.Deadline(); exists {
		if err := conn.SetDeadline(deadline); err != nil {
			engine.removePending(conn)
			conn.Close()
			return nil, nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return conn, stop, nil
}

// Called with mu held. Reserve a separate bounded control slot so a full
// data budget cannot prevent the keepalive that keeps those streams valid.
func (engine *Engine) connectionLimitReached(kind connectionKind) bool {
	count, limit := engine.dialing[kind], maxControlConnections
	if kind == dataConnection {
		count += len(engine.connections)
		limit = maxEngineConnections
	}
	for _, pendingKind := range engine.pending {
		if pendingKind == kind {
			count++
		}
	}
	return count >= limit
}

func (engine *Engine) removePending(conn net.Conn) {
	engine.mu.Lock()
	delete(engine.pending, conn)
	engine.mu.Unlock()
}

func (engine *Engine) recordError(err error) error {
	engine.mu.Lock()
	engine.lastError = err.Error()
	engine.mu.Unlock()
	return err
}

func keepaliveParameters(fields map[string]string) (time.Duration, time.Duration, int) {
	ka, _ := strconv.ParseInt(fields["ka"], 10, 32)
	if ka < 5 {
		ka = 5
	}
	kat, _ := strconv.ParseInt(fields["kat"], 10, 32)
	if kat < 3*ka {
		kat = 3 * ka
	}
	kapf, _ := strconv.ParseInt(fields["kapf"], 10, 32)
	if kapf < 1 {
		kapf = 1
	}
	// Bound untrusted arithmetic to a representable duration. These caps are
	// local resource policy, separate from the observed server clamps.
	const maxKeepaliveSeconds = int64((1<<63 - 1) / int64(time.Second))
	if ka > maxKeepaliveSeconds/kapf {
		ka = maxKeepaliveSeconds / kapf
	}
	if kat > maxKeepaliveSeconds/kapf {
		kat = maxKeepaliveSeconds / kapf
	}
	return time.Duration(ka) * time.Second, time.Duration(kat) * time.Second, int(kapf)
}

func (engine *Engine) keepalive() {
	defer engine.wg.Done()
	ticker := time.NewTicker(keepalivePollInterval)
	defer ticker.Stop()
	failures := 0
	var failureGeneration uint64
	for {
		select {
		case <-engine.ctx.Done():
			return
		case <-ticker.C:
		}
		engine.mu.Lock()
		if engine.closed {
			engine.mu.Unlock()
			return
		}
		if !engine.authenticated {
			engine.mu.Unlock()
			continue
		}
		key, sid, generation := engine.key, engine.sid, engine.generation
		if failureGeneration != generation {
			failureGeneration, failures = generation, 0
		}
		idle, ka, kat := time.Since(engine.lastAlive), engine.ka*time.Duration(engine.kapf), engine.kat*time.Duration(engine.kapf)
		engine.mu.Unlock()
		if idle >= kat {
			engine.failSession(generation, "proxy keepalive timed out")
			continue
		}
		if idle < ka {
			continue
		}
		ctx, cancel := context.WithTimeout(engine.ctx, kat-idle)
		reply, err := engine.control(ctx, key, base64.StdEncoding.EncodeToString([]byte(sid)), map[string]string{"c": "ping", "sid": sid, "t": strconv.FormatInt(time.Now().Unix(), 10)})
		cancel()
		engine.mu.Lock()
		if engine.closed {
			engine.mu.Unlock()
			return
		}
		// A delayed reply belongs to the session that sent the ping, even if
		// a later authentication happens to receive the same textual SID.
		if !engine.authenticated || engine.generation != generation {
			engine.mu.Unlock()
			continue
		}
		if err != nil || reply["c"] != "pong" {
			failures++
			engine.mu.Unlock()
			if failures >= 3 {
				engine.failSession(generation, "proxy keepalive failed")
			}
			continue
		}
		failures = 0
		engine.lastAlive = time.Now()
		engine.mu.Unlock()
	}
}

func (engine *Engine) failSession(generation uint64, message string) {
	engine.mu.Lock()
	if engine.closed || !engine.authenticated || engine.generation != generation {
		engine.mu.Unlock()
		return
	}
	engine.authenticated, engine.lastError = false, message
	clear(engine.key[:])
	engine.sid = ""
	connections := make([]net.Conn, 0, len(engine.pending)+len(engine.connections))
	for conn := range engine.pending {
		connections = append(connections, conn)
	}
	for conn := range engine.connections {
		connections = append(connections, conn)
	}
	engine.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
}

type operationError struct {
	message string
	cause   error
}

func (err *operationError) Error() string { return err.message }
func (err *operationError) Unwrap() error { return err.cause }

func safeError(ctx context.Context, message string, err error) error {
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return &operationError{message: message, cause: err}
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
			return io.ErrNoProgress
		}
	}
	return nil
}
