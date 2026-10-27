package fvproxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

const referenceSID = "local-test/session+id"

type referenceServer struct {
	t           *testing.T
	listener    net.Listener
	privateKey  *rsa.PrivateKey
	mode        string
	stop        chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	key         [16]byte
	requests    atomic.Int32
	pings       atomic.Int32
	targets     chan string
	data        chan []byte
}

func newReferenceServer(t *testing.T, mode string) *referenceServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &referenceServer{t: t, listener: listener, privateKey: key, mode: mode, stop: make(chan struct{}), connections: make(map[net.Conn]struct{}), targets: make(chan string, 8), data: make(chan []byte, 8)}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.connections[conn] = struct{}{}
			server.mu.Unlock()
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				defer conn.Close()
				defer func() { server.mu.Lock(); delete(server.connections, conn); server.mu.Unlock() }()
				server.handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		close(server.stop)
		server.mu.Lock()
		for conn := range server.connections {
			conn.Close()
		}
		server.mu.Unlock()
		server.wg.Wait()
	})
	return server
}

func referenceFields(data []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			result[key] = value
		}
	}
	return result
}

// This deliberately does not use the production outer codec. Its layout is
// fixed by request writer 0x100085910 and reader 0x1000862d0; existing control
// tests additionally compare AES output against independent Node crypto vectors.
func referenceReadOuter(conn net.Conn) ([16]byte, map[string]string, error) {
	var key [16]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		return key, nil, err
	}
	block, _ := aes.NewCipher(key[:])
	stream := cipher.NewCTR(block, make([]byte, 16))
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return key, nil, err
	}
	stream.XORKeyStream(header[:], header[:])
	if header[0] != 0 || header[1] != 0 {
		return key, nil, errors.New("bad outer marker")
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[2:]))
	if _, err := io.ReadFull(conn, payload); err != nil {
		return key, nil, err
	}
	stream.XORKeyStream(payload, payload)
	// The observed writer always terminates the outer header with _= plus
	// 0..199 lowercase bytes, without LF; this is independent of body length.
	paddingStart := bytes.LastIndex(payload, []byte("\n_="))
	if paddingStart < 0 {
		return key, nil, errors.New("missing v2 padding field")
	}
	padding := payload[paddingStart+3:]
	if len(padding) > 199 {
		return key, nil, errors.New("v2 padding exceeds observed range")
	}
	for _, char := range padding {
		if char < 'a' || char > 'z' {
			return key, nil, errors.New("v2 padding contains non-lowercase byte or trailing newline")
		}
	}
	return key, referenceFields(payload), nil
}

func referenceCTR(key, nonce [16]byte) cipher.Stream {
	block, _ := aes.NewCipher(key[:])
	return cipher.NewCTR(block, nonce[:])
}

func referenceReply(conn net.Conn, key [16]byte, payload string) error {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(frame[2:], uint16(len(payload)))
	copy(frame[4:], payload)
	referenceCTR(key, [16]byte{}).XORKeyStream(frame, frame)
	// Make short reads routine instead of relying on packet coalescing.
	for len(frame) > 0 {
		n := min(3, len(frame))
		if _, err := conn.Write(frame[:n]); err != nil {
			return err
		}
		frame = frame[n:]
	}
	return nil
}

func (server *referenceServer) handle(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	outerKey, header, err := referenceReadOuter(conn)
	if err != nil {
		return
	}
	server.requests.Add(1)
	nonceBytes, err := hex.DecodeString(header["n"])
	if err != nil || len(nonceBytes) != 16 {
		server.t.Error("nonce was not16-byte lowercase hex")
		return
	}
	var nonce [16]byte
	copy(nonce[:], nonceBytes)
	if header["s"] != "" {
		server.handleStream(conn, outerKey, nonce, header)
		return
	}
	if server.mode == "block" {
		<-server.stop
		return
	}
	if server.mode == "truncated" {
		conn.Write([]byte{0, 0})
		return
	}
	if server.mode == "outer oversized" {
		frame := []byte{0, 0, 0x10, 0x01}
		referenceCTR(outerKey, [16]byte{}).XORKeyStream(frame, frame)
		conn.Write(frame)
		return
	}
	wrapped, err := base64.StdEncoding.DecodeString(header["k"])
	if err != nil {
		server.t.Error("control k was not standard Base64")
		return
	}
	server.mu.Lock()
	key := server.key
	server.mu.Unlock()
	if bytes.HasPrefix(wrapped, []byte("OAEP")) {
		if len(wrapped) != 132 {
			server.t.Error("unexpected RSA envelope width")
			return
		}
		// SHA224+empty label is independently established by the descriptor,
		// dispatch and standard SHA224 IV at0x100147c38/0x10014a0b0.
		plain, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, server.privateKey, wrapped[4:], nil)
		if err != nil || len(plain) != 16 {
			server.t.Error("RSA-OAEP parameters mismatch")
			return
		}
		copy(key[:], plain)
		server.mu.Lock()
		server.key = key
		server.mu.Unlock()
	} else if string(wrapped) != referenceSID {
		server.t.Error("ping k did not Base64-encode sid")
		return
	}
	length, err := strconv.Atoi(header["l"])
	if err != nil || length <= 0 || length > maxControlBodyBytes {
		server.t.Error("invalid control body length")
		return
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}
	referenceCTR(key, nonce).XORKeyStream(body, body)
	paddingStart := bytes.LastIndex(body, []byte("\n_="))
	if paddingStart < 0 || len(body) >= 1360 {
		server.t.Error("control body lacks observed inner padding or exceeds padding budget")
		return
	}
	for _, char := range body[paddingStart+3:] {
		if char < 'a' || char > 'z' {
			server.t.Error("control body padding is not lowercase or has trailing LF")
			return
		}
	}
	mapBody := body[:paddingStart+1]
	fields := referenceFields(mapBody)
	response := "c=aur\nr=ok\nsid=" + referenceSID + "\nka=5\nkat=15\nkapf=1\n"
	if fields["c"] == "ping" {
		server.pings.Add(1)
		if fields["sid"] != referenceSID {
			server.t.Error("ping body sid mismatch")
		}
		response = "c=pong\n"
		if server.mode == "bad pong" {
			response = "c=invalid\n"
		}
	} else {
		if fields["c"] != "au" || fields["u"] != "offline-user" || fields["p"] != "offline-password" || fields["dim"] != "lid=anonymous" {
			server.t.Error("authentication fields mismatch")
		}
		if _, err := strconv.ParseInt(fields["t"], 10, 64); err != nil {
			server.t.Error("auth timestamp is not decimal seconds")
		}
		var keys []string
		for _, line := range strings.Split(string(mapBody), "\n") {
			if k, _, ok := strings.Cut(line, "="); ok {
				keys = append(keys, k)
			}
		}
		if strings.Join(keys, ",") != "c,ce,cseid,cuid,cv,dim,osd,osp,osv,p,peip,st,t,u,v" {
			server.t.Error("authentication fields are not sorted LF entries")
		}
		switch server.mode {
		case "rejected":
			response = "c=aur\nr=denied\nfm=offline-password private-seed private-token\n"
		case "missing sid":
			response = "c=aur\nr=ok\n"
		case "malformed":
			response = "c=aur\nmalformed\n"
		case "unknown command":
			response = "c=unexpected\nr=denied\n"
		case "missing result":
			response = "c=aur\nsid=" + referenceSID + "\n"
		case "empty result":
			response = "c=aur\nr=\n"
		case "empty body":
			response = ""
		case "body oversized":
			response = strings.Repeat("x", maxControlBodyBytes+1)
		}
	}
	code := "code=200\n"
	if server.mode == "outer rejected" {
		code = "code=403\n"
	}
	if server.mode == "crlf" {
		code = "code=200\r\n"
		response = strings.ReplaceAll(response, "\n", "\r\n")
	}
	if err := referenceReply(conn, outerKey, code); err != nil {
		return
	}
	data := []byte(response)
	referenceCTR(key, nonce).XORKeyStream(data, data)
	writeAll(conn, data)
}

func (server *referenceServer) handleStream(conn net.Conn, outerKey, nonce [16]byte, header map[string]string) {
	if header["s"] != referenceSID || header["k"] != "" {
		server.t.Error("stream header sid/key mismatch")
		return
	}
	if _, ok := header["l"]; ok {
		server.t.Error("stream header must omit length")
		return
	}
	server.mu.Lock()
	key := server.key
	server.mu.Unlock()
	rx, tx := referenceCTR(key, nonce), referenceCTR(key, nonce)
	reader := &cipher.StreamReader{S: rx, R: conn}
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return
	}
	if !bytes.Equal(prefix[:3], []byte{5, 1, 0}) {
		server.t.Error("not SOCKS5 CONNECT")
		return
	}
	var host string
	switch prefix[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return
		}
		name := make([]byte, size[0])
		if _, err := io.ReadFull(reader, name); err != nil {
			return
		}
		host = string(name)
	default:
		server.t.Error("unsupported CONNECT target type")
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return
	}
	server.targets <- net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))
	code := "code=200\n"
	if server.mode == "crlf" {
		code = "code=200\r\n"
	}
	if err := referenceReply(conn, outerKey, code); err != nil {
		return
	}
	writer := &cipher.StreamWriter{S: tx, W: conn}
	if _, err := writer.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	if server.mode == "half close" {
		conn.(*net.TCPConn).CloseWrite()
		data, _ := io.ReadAll(reader)
		server.data <- data
		return
	}
	io.Copy(writer, reader)
}

func referenceConfig(server *referenceServer) Config {
	return Config{Address: server.listener.Addr().String(), PublicKey: &server.privateKey.PublicKey, Authentication: map[string]string{
		"u": "offline-user", "p": "offline-password", "cuid": "anonymous", "cseid": "anonymous-env", "st": "ajs", "v": "4.3.0.1", "cv": "4.9.6.0", "osp": "linux", "osd": "x86_64", "osv": "test OS", "dim": "lid=anonymous", "peip": "", "ce": "test-value",
	}, Timeout: 2 * time.Second}
}

func referenceEngine(t *testing.T, server *referenceServer) *Engine {
	t.Helper()
	engine, err := NewEngine(referenceConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

type fragmentConn struct{ net.Conn }

func (conn fragmentConn) Read(p []byte) (int, error)  { return conn.Conn.Read(p[:min(len(p), 3)]) }
func (conn fragmentConn) Write(p []byte) (int, error) { return conn.Conn.Write(p[:min(len(p), 5)]) }
func (conn fragmentConn) CloseWrite() error           { return conn.Conn.(*net.TCPConn).CloseWrite() }
func (conn fragmentConn) CloseRead() error            { return conn.Conn.(*net.TCPConn).CloseRead() }

func TestEngineAuthenticateAndRawTCPStream(t *testing.T) {
	server := newReferenceServer(t, "")
	config := referenceConfig(server)
	config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != server.listener.Addr().String() || network != "tcp" {
			t.Error("dial resolved the target locally")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return fragmentConn{conn}, nil
	}
	engine, err := NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1:80", "remote-resolution-only.invalid:443"} {
		conn, err := engine.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		if got := <-server.targets; got != target {
			t.Fatalf("target=%s", got)
		}
		if status := engine.Status(); !status.Authenticated || status.ActiveConnections != 1 {
			t.Fatalf("status=%+v", status)
		}
		payload := bytes.Repeat([]byte("stream bytes across chunk boundaries\x00"), 2500)
		finished := make(chan error, 1)
		go func() { _, err := conn.Write(payload); finished <- err }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; err != nil || !bytes.Equal(got, payload) {
			t.Fatal("stream cipher continuity failed")
		}
		conn.Close()
		if engine.Status().ActiveConnections != 0 {
			t.Fatal("closed stream retained")
		}
	}
	if server.requests.Load() != 3 {
		t.Fatal("unexpected control/data request count")
	}
}

func TestEngineCRLFControlAndStreamReplies(t *testing.T) {
	server := newReferenceServer(t, "crlf")
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatalf("CRLF authentication failed: %v", err)
	}
	conn, err := engine.DialContext(context.Background(), "tcp", "public-fixture.invalid:443")
	if err != nil {
		t.Fatalf("CRLF stream handshake failed: %v", err)
	}
	defer conn.Close()
	const message = "public fixture stream after CRLF headers"
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != message {
		t.Fatalf("CRLF stream response failed: %v", err)
	}
}

func TestV2PaddingObservedBoundsAndNoTrailingLF(t *testing.T) {
	for _, size := range []int{0, 199} {
		randomBytes := append([]byte{byte(size)}, bytes.Repeat([]byte{255}, size)...)
		engine := &Engine{random: bytes.NewReader(randomBytes)}
		original := []byte("s=\nn=public-nonce\nk=public-envelope\nl=17\n")
		payload, err := engine.paddedV2Payload(append([]byte(nil), original...))
		if err != nil || !bytes.Equal(payload[:len(original)], original) || string(payload[len(original):]) != "_="+strings.Repeat("v", size) || bytes.HasSuffix(payload, []byte("\n")) {
			t.Fatalf("padding boundary %d mismatch: %v", size, err)
		}
	}
}

func TestControlBodyPaddingBudgetAndFullWidthRandomLength(t *testing.T) {
	for _, test := range []struct {
		name           string
		bodyLength     int
		randomLength   uint32
		paddingLength  int
		paddingPresent bool
	}{
		{"more-than-byte-range", 5, 500, 500, true},
		{"maximum-final-length", 5, 1352, 1352, true},
		{"only-padding-marker-fits", 1357, 333, 0, true},
		{"two-bytes-available", 1358, 0, 0, false},
		{"at-budget", 1360, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte("c=" + strings.Repeat("x", test.bodyLength-3) + "\n")
			original := append([]byte(nil), body...)
			engine := &Engine{random: errorReader{}}
			if test.paddingPresent {
				var length [4]byte
				binary.BigEndian.PutUint32(length[:], test.randomLength)
				engine.random = bytes.NewReader(append(length[:], bytes.Repeat([]byte{25}, test.paddingLength)...))
			}
			padded, err := engine.paddedControlBody(body)
			if err != nil || len(padded) < len(original) || !bytes.Equal(padded[:len(original)], original) {
				t.Fatalf("inner padding changed plaintext or read unnecessary randomness: %v", err)
			}
			wantLength := len(original)
			if test.paddingPresent {
				wantLength += 2 + test.paddingLength
				if string(padded[len(original):]) != "_="+strings.Repeat("z", test.paddingLength) || bytes.HasSuffix(padded, []byte("\n")) {
					t.Fatal("inner padding differs from the observed unterminated field")
				}
			}
			if len(padded) != wantLength {
				t.Fatalf("inner padding length = %d, want %d", len(padded), wantLength)
			}
		})
	}
}

func TestControlBodyPaddingRandomFailureDoesNotDialOrLeak(t *testing.T) {
	const privateDiagnostic = "PUBLIC_FIXTURE_INNER_RANDOM_ERROR_NEVER_PRINT"
	for _, content := range []bool{false, true} {
		t.Run(strconv.FormatBool(content), func(t *testing.T) {
			server := newReferenceServer(t, "")
			config := referenceConfig(server)
			config.DialContext = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("inner padding randomness failure dialed the network")
				return nil, nil
			}
			prefix := []byte(nil)
			if content {
				prefix = []byte{0, 0, 0, 1}
			}
			config.Random = io.MultiReader(bytes.NewReader(prefix), iotest.ErrReader(errors.New(privateDiagnostic)))
			engine, err := NewEngine(config)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			_, err = engine.control(context.Background(), [16]byte{}, "public-envelope", map[string]string{"c": "au"})
			if err == nil || strings.Contains(err.Error(), privateDiagnostic) || !strings.Contains(err.Error(), "proxy random generation failed") {
				t.Fatalf("inner padding failure leaked diagnostic or succeeded: %v", err)
			}
		})
	}
}

func TestV2PaddingRandomFailurePreventsControlAndStreamDial(t *testing.T) {
	const privateDiagnostic = "PUBLIC_FIXTURE_RANDOM_ERROR_NEVER_PRINT"
	for _, stage := range []string{"length", "content"} {
		for _, stream := range []bool{false, true} {
			t.Run(stage+strconv.FormatBool(stream), func(t *testing.T) {
				server := newReferenceServer(t, "")
				config := referenceConfig(server)
				var dials atomic.Int32
				config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					dials.Add(1)
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
				engine, err := NewEngine(config)
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				if stream {
					if err := engine.Authenticate(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				prefixLength := 32 // Fresh nonce and outer key precede outer padding.
				if !stream {
					prefixLength += 4 // A zero-length inner padding sample comes first.
				}
				prefix := make([]byte, prefixLength)
				if stage == "content" {
					prefix = append(prefix, 1) // Request one padding byte, then fail.
				}
				engine.randomMu.Lock()
				engine.random = io.MultiReader(bytes.NewReader(prefix), iotest.ErrReader(errors.New(privateDiagnostic)))
				engine.randomMu.Unlock()
				before := dials.Load()
				if stream {
					_, err = engine.DialContext(context.Background(), "tcp", "public-fixture.invalid:443")
				} else {
					_, err = engine.control(context.Background(), [16]byte{}, "public-envelope", map[string]string{"c": "au"})
				}
				if err == nil || dials.Load() != before || strings.Contains(err.Error(), privateDiagnostic) || !strings.Contains(err.Error(), "proxy random generation failed") {
					t.Fatalf("padding failure was unsafe or dialed: before=%d after=%d error=%v", before, dials.Load(), err)
				}
			})
		}
	}
}

func TestEngineHalfClosePreservesOtherDirection(t *testing.T) {
	server := newReferenceServer(t, "half close")
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := engine.DialContext(context.Background(), "tcp", "target.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := conn.Read(data[:]); err != io.EOF {
		t.Fatalf("read error=%v", err)
	}
	if _, err := conn.Write([]byte("after remote EOF")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := <-server.data; string(got) != "after remote EOF" {
		t.Fatal("half close lost pending write")
	}
	if engine.Status().ActiveConnections != 0 {
		t.Fatal("completed half closes retained stream")
	}
}

func TestEngineRejectsInvalidResponses(t *testing.T) {
	for _, mode := range []string{"rejected", "missing sid", "malformed", "unknown command", "missing result", "empty result", "empty body", "body oversized", "outer rejected", "outer oversized", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			server := newReferenceServer(t, mode)
			engine := referenceEngine(t, server)
			err := engine.Authenticate(context.Background())
			if err == nil || engine.Status().Authenticated {
				t.Fatal("invalid reply authenticated")
			}
			for _, secret := range []string{"offline-password", "private-seed", "private-token", referenceSID} {
				if strings.Contains(err.Error(), secret) || strings.Contains(engine.Status().LastError, secret) {
					t.Fatal("error disclosed private data")
				}
			}
			if mode == "rejected" && !errors.Is(err, ErrProxyAuthRejected) {
				t.Fatal("auth failure not classified")
			}
			if mode != "rejected" && (!errors.Is(err, ErrProxyProtocol) || errors.Is(err, ErrProxyAuthRejected)) {
				t.Fatal("malformed or incompatible reply was classified as authentication rejection")
			}
		})
	}
}

func TestEngineContextAndCloseCancelPending(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			server := newReferenceServer(t, "block")
			engine := referenceEngine(t, server)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := context.Canceled
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				want = context.DeadlineExceeded
			}
			finished := make(chan error, 1)
			go func() { finished <- engine.Authenticate(ctx) }()
			waitFor(t, func() bool { return server.requests.Load() > 0 })
			if mode == "cancel" {
				cancel()
			}
			if mode == "close" {
				engine.Close()
			}
			select {
			case err := <-finished:
				if err == nil || mode != "close" && !errors.Is(err, want) {
					t.Fatalf("error=%v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("pending auth did not stop")
			}
			if engine.Status().Authenticated {
				t.Fatal("canceled auth authenticated")
			}
		})
	}
}

func TestEngineCloseCancelsDialInProgress(t *testing.T) {
	server := newReferenceServer(t, "")
	config := referenceConfig(server)
	started := make(chan struct{})
	config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	engine, err := NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- engine.Authenticate(context.Background()) }()
	<-started
	engine.Close()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close left dial running")
	}
}

func TestEngineAuthenticationQueueHonorsCancellation(t *testing.T) {
	server := newReferenceServer(t, "block")
	engine := referenceEngine(t, server)
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first := make(chan error, 1)
	go func() { first <- engine.Authenticate(firstContext) }()
	waitFor(t, func() bool { return server.requests.Load() == 1 })
	secondContext, cancelSecond := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelSecond()
	if err := engine.Authenticate(secondContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued authentication ignored its deadline: %v", err)
	}
	cancelFirst()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first authentication did not cancel: %v", err)
	}
	if server.requests.Load() != 1 {
		t.Fatal("queued canceled authentication sent another request")
	}
}

func TestEngineCloseUnblocksActiveStream(t *testing.T) {
	server := newReferenceServer(t, "")
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := engine.DialContext(context.Background(), "tcp", "target.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { var b [1]byte; _, err := conn.Read(b[:]); finished <- err }()
	engine.Close()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed connection read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close left active read blocked")
	}
	if status := engine.Status(); status.Authenticated || status.ActiveConnections != 0 {
		t.Fatal("closed engine retained active state")
	}
}

func TestEngineKeepaliveFailureInvalidatesSession(t *testing.T) {
	server := newReferenceServer(t, "bad pong")
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.lastAlive = time.Now().Add(-6 * time.Second)
	engine.mu.Unlock()
	waitFor(t, func() bool { status := engine.Status(); return !status.Authenticated && status.ActiveConnections == 0 })
	if server.pings.Load() != 3 || engine.Status().LastError == "" {
		t.Fatal("keepalive failure did not end the session after three failures")
	}
}

func TestEngineDataConnectionBudgetBeforeDial(t *testing.T) {
	server := newReferenceServer(t, "")
	config := referenceConfig(server)
	config.DialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("connection budget allowed a dial")
		return nil, errors.New("unexpected dial")
	}
	engine, err := NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.mu.Lock()
	engine.dialing[dataConnection] = maxEngineConnections
	engine.authenticated = true
	engine.mu.Unlock()
	if _, err := engine.DialContext(context.Background(), "tcp", "target.invalid:80"); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("budget error = %v", err)
	}
}

func TestEngineKeepaliveAndShutdown(t *testing.T) {
	server := newReferenceServer(t, "")
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.lastAlive = time.Now().Add(-6 * time.Second)
	engine.mu.Unlock()
	waitFor(t, func() bool { return server.pings.Load() > 0 })
	if !engine.Status().Authenticated {
		t.Fatal("valid pong ended session")
	}
	conn, err := engine.DialContext(context.Background(), "tcp", "target.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.lastAlive = time.Now().Add(-20 * time.Second)
	engine.mu.Unlock()
	waitFor(t, func() bool { status := engine.Status(); return !status.Authenticated && status.ActiveConnections == 0 })
	if engine.Status().ActiveConnections != 0 {
		t.Fatal("expired session left data connections")
	}
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("expired session remained writable")
	}
	engine.Close()
	engine.mu.Lock()
	credentialsCleared := engine.authentication == nil && engine.sid == "" && engine.key == [16]byte{}
	engine.mu.Unlock()
	if !credentialsCleared {
		t.Fatal("Close retained authentication references")
	}
}

func TestEngineValidationAndNoEagerActions(t *testing.T) {
	server := newReferenceServer(t, "")
	config := referenceConfig(server)
	config.Random = errorReader{}
	config.DialContext = func(context.Context, string, string) (net.Conn, error) { t.Fatal("NewEngine dialed"); return nil, nil }
	engine, err := NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	engine.Close()
	for _, field := range []string{"u", "p", "cuid", "cseid", "st", "v", "cv", "osp", "osd", "osv", "dim", "peip", "ce"} {
		cfg := referenceConfig(server)
		delete(cfg.Authentication, field)
		if _, err := NewEngine(cfg); err == nil {
			t.Errorf("accepted missing %s", field)
		}
	}
	for _, target := range []string{"[::1]:80", "host:0", "host:65536", "host", "\x00host:80"} {
		if _, err := connectRequest("tcp", target); err == nil {
			t.Errorf("accepted target %q", target)
		}
	}
	engine = referenceEngine(t, server)
	if _, err := engine.DialContext(context.Background(), "tcp", "host:80"); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal("unauthenticated dial accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("must not read randomness") }

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
