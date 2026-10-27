package localproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (function dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

type proxyFixture struct {
	server *Server
	addr   string
	cancel context.CancelFunc
	done   <-chan error
}

func startProxy(t *testing.T, config Config) proxyFixture {
	t.Helper()
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	fixture := proxyFixture{server, listener.Addr().String(), cancel, done}
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return fixture
}

func connectProxy(t *testing.T, fixture proxyFixture) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fixture.addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tcp := conn.(*net.TCPConn)
	_ = tcp.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { _ = tcp.Close() })
	return tcp
}

func readExact(t *testing.T, reader io.Reader, expected []byte) {
	t.Helper()
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, actual); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("bytes = %v, want %v", actual, expected)
	}
}

func echoTarget(t *testing.T, afterEOF bool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				if afterEOF {
					data, err := io.ReadAll(conn)
					if err == nil {
						_, _ = conn.Write(append([]byte("after-eof:"), data...))
					}
					return
				}
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr().String()
}

func targetDialer(target string, calls chan<- string) Dialer {
	return dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("unexpected network")
		}
		if calls != nil {
			calls <- address
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	})
}

func TestSOCKSConnectAddressesAndBufferedPayload(t *testing.T) {
	cases := []struct {
		name    string
		address []byte
		want    string
	}{
		{"ipv4", []byte{1, 192, 0, 2, 1}, "192.0.2.1:443"},
		{"domain", append([]byte{3, 12}, []byte("example.test")...), "example.test:443"},
		{"ipv6", append([]byte{4}, net.ParseIP("2001:db8::1").To16()...), "[2001:db8::1]:443"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			calls := make(chan string, 1)
			fixture := startProxy(t, Config{Dialer: targetDialer(echoTarget(t, false), calls)})
			conn := connectProxy(t, fixture)
			_, _ = conn.Write([]byte{5, 1, 0})
			readExact(t, conn, []byte{5, 0})
			request := append([]byte{5, 1, 0}, test.address...)
			request = append(request, 1, 187)
			request = append(request, []byte("buffered-payload")...)
			_, _ = conn.Write(request)
			readExact(t, conn, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			readExact(t, conn, []byte("buffered-payload"))
			if actual := <-calls; actual != test.want {
				t.Fatalf("dial = %q, want %q", actual, test.want)
			}
		})
	}
}

func TestSOCKSAuthentication(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(fmt.Sprint(success), func(t *testing.T) {
			var calls atomic.Int32
			fixture := startProxy(t, Config{
				Username: "local-user", Password: []byte("local-secret"),
				Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
					calls.Add(1)
					return nil, errors.New("sensitive upstream diagnostic")
				}),
			})
			conn := connectProxy(t, fixture)
			_, _ = conn.Write([]byte{5, 2, 0, 2})
			readExact(t, conn, []byte{5, 2})
			password := "wrong-secret"
			if success {
				password = "local-secret"
			}
			request := append([]byte{1, 10}, []byte("local-user")...)
			request = append(request, byte(len(password)))
			request = append(request, []byte(password)...)
			_, _ = conn.Write(request)
			status := byte(1)
			if success {
				status = 0
			}
			readExact(t, conn, []byte{1, status})
			if success {
				_, _ = conn.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 80})
				readExact(t, conn, []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			}
			remaining, err := io.ReadAll(conn)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("unexpected authentication output: %q, %v", remaining, err)
			}
			if actual := calls.Load(); actual != map[bool]int32{false: 0, true: 1}[success] {
				t.Fatalf("dial calls = %d", actual)
			}
		})
	}
}

func TestSOCKSRejectsInvalidAndUnsupportedWithoutDial(t *testing.T) {
	cases := []struct {
		name    string
		auth    bool
		request []byte
		want    []byte
	}{
		{"no-matching-method", true, []byte{5, 1, 0}, []byte{5, 255}},
		{"no-methods", false, []byte{5, 0}, []byte{5, 255}},
		{"bind", false, []byte{5, 1, 0, 5, 2, 0, 1}, []byte{5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"udp", false, []byte{5, 1, 0, 5, 3, 0, 1}, []byte{5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"invalid-reserved", false, []byte{5, 1, 0, 5, 1, 1, 1}, []byte{5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"invalid-atyp", false, []byte{5, 1, 0, 5, 1, 0, 9}, []byte{5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"zero-port", false, []byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 0}, []byte{5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0}},
		{"bad-domain", false, []byte{5, 1, 0, 5, 1, 0, 3, 3, 'a', 0, 'b'}, []byte{5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			config := Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("must not dial")
			})}
			if test.auth {
				config.Username, config.Password = "user", []byte("secret")
			}
			fixture := startProxy(t, config)
			conn := connectProxy(t, fixture)
			_, _ = conn.Write(test.request)
			readExact(t, conn, test.want)
			_, _ = io.ReadAll(conn)
			if calls.Load() != 0 {
				t.Fatal("invalid request dialed upstream")
			}
		})
	}
}

func TestTunnelPreservesHalfClose(t *testing.T) {
	for _, protocol := range []string{"socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			fixture := startProxy(t, Config{Dialer: targetDialer(echoTarget(t, true), nil)})
			conn := connectProxy(t, fixture)
			var reader io.Reader = conn
			if protocol == "socks" {
				_, _ = conn.Write([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80})
				readExact(t, conn, []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			} else {
				_, _ = io.WriteString(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
				buffered := bufio.NewReader(conn)
				response, err := http.ReadResponse(buffered, &http.Request{Method: http.MethodConnect})
				if err != nil || response.StatusCode != 200 {
					t.Fatalf("CONNECT = %v, %v", response, err)
				}
				reader = buffered
			}
			_, _ = io.WriteString(conn, "finish-request")
			_ = conn.CloseWrite()
			output, err := io.ReadAll(reader)
			if err != nil || string(output) != "after-eof:finish-request" {
				t.Fatalf("half-close output = %q, %v", output, err)
			}
		})
	}
}

func TestHTTPConnectKeepsBufferedTunnelData(t *testing.T) {
	calls := make(chan string, 1)
	fixture := startProxy(t, Config{Dialer: targetDialer(echoTarget(t, false), calls)})
	conn := connectProxy(t, fixture)
	_, _ = io.WriteString(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\nfirst-tunnel-bytes")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT = %v, %v", response, err)
	}
	readExact(t, reader, []byte("first-tunnel-bytes"))
	if actual := <-calls; actual != "example.test:443" {
		t.Fatalf("dial = %q", actual)
	}
}

func TestHTTPForwardStreamsAndRemovesProxyCredentials(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			body := ""
			if method == http.MethodPost {
				body = strings.Repeat("streaming-request-", 65536)
			}
			received := make(chan error, 1)
			target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				payload, err := io.ReadAll(request.Body)
				if err == nil && string(payload) != body {
					err = errors.New("incorrect request body")
				}
				for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Remove", "Proxy-Authenticate"} {
					if request.Header.Get(name) != "" {
						err = fmt.Errorf("hop header %s leaked", name)
					}
				}
				if request.RequestURI != "/path?q=1" || request.Host != "example.test:8080" || request.Method != method {
					err = errors.New("incorrect origin request")
				}
				received <- err
				// Keep the original Connection field: net/http's regular server
				// writer replaces it when the request itself asks to close.
				conn, buffered, hijackErr := writer.(http.Hijacker).Hijack()
				if hijackErr != nil {
					return
				}
				defer conn.Close()
				payload = []byte("response:" + method)
				_, _ = fmt.Fprintf(buffered, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: X-Origin-Hop\r\nX-Origin-Hop: must-remove\r\nProxy-Authenticate: must-remove\r\n\r\n%s", len(payload), payload)
				_ = buffered.Flush()
			}))
			defer target.Close()
			calls := make(chan string, 1)
			fixture := startProxy(t, Config{
				Dialer:   targetDialer(strings.TrimPrefix(target.URL, "http://"), calls),
				Username: "local-user", Password: []byte("local-secret"),
			})
			conn := connectProxy(t, fixture)
			credentials := base64.StdEncoding.EncodeToString([]byte("local-user:local-secret"))
			_, _ = fmt.Fprintf(conn, "%s http://example.test:8080/path?q=1 HTTP/1.1\r\nHost: ignored.test\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\nConnection: X-Remove\r\nX-Remove: secret-hop-value\r\nContent-Length: %d\r\n\r\n%s", method, credentials, len(body), body)
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || string(payload) != "response:"+method || !response.Close {
				t.Fatalf("forward = %d %q close=%v, %v", response.StatusCode, payload, response.Close, err)
			}
			if response.Header.Get("X-Origin-Hop") != "" || response.Header.Get("Proxy-Authenticate") != "" {
				t.Fatal("response hop headers leaked")
			}
			if err := <-received; err != nil {
				t.Fatal(err)
			}
			if actual := <-calls; actual != "example.test:8080" {
				t.Fatalf("dial = %q", actual)
			}
		})
	}
}

func TestHTTPRejectsWithoutDialOrSensitiveErrors(t *testing.T) {
	credentials := base64.StdEncoding.EncodeToString([]byte("local-user:local-secret"))
	cases := []struct {
		name, request string
		status        int
	}{
		{"missing-auth", "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", 407},
		{"wrong-auth", "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("local-user:wrong-secret")) + "\r\n\r\n", 407},
		{"userinfo", "GET http://url-user:url-secret@example.test/ HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n", 400},
		{"connect-userinfo", "CONNECT url-user:url-secret@example.test:443 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n", 400},
		{"origin-form", "GET /path HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n", 400},
		{"zero-port", "CONNECT example.test:0 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n", 400},
		{"https-absolute", "GET https://example.test/ HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n", 400},
		{"bad-method", "BAD METHOD http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", 400},
		{"header-bound", "GET http://example.test/ HTTP/1.1\r\nX-Large: " + strings.Repeat("x", MaxHeaderBytes) + "\r\n\r\n", 431},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			fixture := startProxy(t, Config{
				Username: "local-user", Password: []byte("local-secret"),
				Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
					calls.Add(1)
					return nil, errors.New("sensitive-target-secret")
				}),
			})
			conn := connectProxy(t, fixture)
			_, _ = io.WriteString(conn, test.request)
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			output, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != test.status || calls.Load() != 0 {
				t.Fatalf("status=%d calls=%d, %v", response.StatusCode, calls.Load(), err)
			}
			for _, secret := range []string{"local-user", "local-secret", "wrong-secret", "url-user", "url-secret", "sensitive-target-secret", credentials} {
				if strings.Contains(string(output), secret) || strings.Contains(fmt.Sprint(response.Header), secret) {
					t.Fatal("sensitive diagnostic leaked")
				}
			}
			if test.status == 407 && response.Header.Get("Proxy-Authenticate") == "" {
				t.Fatal("missing proxy authentication challenge")
			}
		})
	}
}

func TestHTTPChunkedContinueStreamsAndDropsTrailers(t *testing.T) {
	prefixReceived := make(chan struct{})
	checked := make(chan error, 1)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		prefix := make([]byte, 5)
		_, err := io.ReadFull(request.Body, prefix)
		if err == nil && string(prefix) != "first" {
			err = errors.New("incorrect streaming prefix")
		}
		close(prefixReceived)
		remainder, readErr := io.ReadAll(request.Body)
		if err == nil {
			err = readErr
		}
		if err == nil && string(remainder) != "-second" {
			err = errors.New("incorrect streaming remainder")
		}
		if request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("Expect") != "" || len(request.Trailer) != 0 {
			err = errors.New("proxy credentials or client trailers were forwarded")
		}
		checked <- err
		_, _ = io.WriteString(writer, "streamed")
	}))
	defer target.Close()
	fixture := startProxy(t, Config{Dialer: targetDialer(strings.TrimPrefix(target.URL, "http://"), nil)})
	conn := connectProxy(t, fixture)
	_, _ = io.WriteString(conn, "POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Trace\r\nProxy-Authorization: Basic cHVibGljOnRlc3Q=\r\nExpect: 100-continue\r\n\r\n")
	reader := bufio.NewReader(conn)
	interim, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil || interim.StatusCode != http.StatusContinue {
		t.Fatalf("Continue = %v, %v", interim, err)
	}
	_, _ = io.WriteString(conn, "5\r\nfirst\r\n")
	select {
	case <-prefixReceived:
	case <-time.After(time.Second):
		t.Fatal("proxy buffered the request instead of streaming its prefix")
	}
	_, _ = io.WriteString(conn, "7\r\n-second\r\n0\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\nX-Trace: private-trailer\r\n\r\n")
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(output) != "streamed" {
		t.Fatalf("chunked response = %d %q, %v", response.StatusCode, output, err)
	}
	if err := <-checked; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPDialFailureDoesNotDrainBodyOrFallBackToDirect(t *testing.T) {
	directTarget, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer directTarget.Close()
	var calls atomic.Int32
	fixture := startProxy(t, Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("PUBLIC_FIXTURE_UPSTREAM_SECRET")
	})})
	conn := connectProxy(t, fixture)
	// Keep the request body open. A failed dial must not try to drain it.
	_, _ = fmt.Fprintf(conn, "POST http://%s/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1048576\r\n\r\n", directTarget.Addr())
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 502 || calls.Load() != 1 || strings.Contains(string(output), "PUBLIC_FIXTURE_UPSTREAM_SECRET") {
		t.Fatalf("dial failure = %d %q calls=%d, %v", response.StatusCode, output, calls.Load(), err)
	}
	_ = directTarget.SetDeadline(time.Now().Add(30 * time.Millisecond))
	if direct, err := directTarget.Accept(); err == nil {
		_ = direct.Close()
		t.Fatal("dial failure fell back to direct access")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("direct target check: %v", err)
	}
}

func TestHTTPEarlyResponseDoesNotWaitForClientUpload(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = io.WriteString(writer, "too large")
	}))
	defer target.Close()
	fixture := startProxy(t, Config{Dialer: targetDialer(strings.TrimPrefix(target.URL, "http://"), nil)})
	conn := connectProxy(t, fixture)
	_, _ = io.WriteString(conn, "POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2097152\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 413 || string(output) != "too large" {
		t.Fatalf("early response = %d %q, %v", response.StatusCode, output, err)
	}
}

func TestHandshakeTimeoutAndDialCancellation(t *testing.T) {
	t.Run("incomplete-client", func(t *testing.T) {
		var calls atomic.Int32
		fixture := startProxy(t, Config{HandshakeTimeout: 50 * time.Millisecond, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("must not dial")
		})})
		conn := connectProxy(t, fixture)
		_, _ = conn.Write([]byte{5})
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("incomplete handshake remained open")
		}
		if calls.Load() != 0 {
			t.Fatal("incomplete handshake dialed")
		}
	})
	t.Run("pending-dial", func(t *testing.T) {
		started := make(chan struct{})
		ended := make(chan struct{})
		fixture := startProxy(t, Config{HandshakeTimeout: 50 * time.Millisecond, Dialer: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			close(ended)
			return nil, ctx.Err()
		})})
		conn := connectProxy(t, fixture)
		_, _ = io.WriteString(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
		<-started
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		// The shared handshake deadline also bounds an error reply. It may
		// close the socket before that reply can be written.
		if err == nil {
			if response.StatusCode != 502 {
				t.Fatalf("timeout status = %d", response.StatusCode)
			}
			_ = response.Body.Close()
		} else if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Fatalf("timeout = %v", err)
		}
		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Fatal("dial was not canceled")
		}
	})
}

func TestCloseAndContextCancelInterruptSessions(t *testing.T) {
	for _, stop := range []string{"close", "cancel"} {
		t.Run(stop, func(t *testing.T) {
			upstreamClosed := make(chan struct{})
			fixture := startProxy(t, Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
				upstream, target := net.Pipe()
				go func() { _, _ = io.Copy(io.Discard, target); _ = target.Close(); close(upstreamClosed) }()
				return upstream, nil
			})})
			idle := connectProxy(t, fixture)
			active := connectProxy(t, fixture)
			_, _ = active.Write([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80})
			readExact(t, active, []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			if stop == "close" {
				if err := fixture.server.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				fixture.cancel()
			}
			for _, conn := range []net.Conn{idle, active} {
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("client was not closed")
				}
			}
			select {
			case <-upstreamClosed:
			case <-time.After(time.Second):
				t.Fatal("upstream was not closed")
			}
			if conn, err := net.DialTimeout("tcp", fixture.addr, time.Second); err == nil {
				_ = conn.Close()
				t.Fatal("listener was not closed")
			}
			_ = fixture.server.Close()
			fixture.server.mu.Lock()
			remaining := len(fixture.server.conns)
			fixture.server.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("connections still tracked after Close: %d", remaining)
			}
		})
	}
}

func TestCloseCancelsPendingDial(t *testing.T) {
	for _, request := range []string{
		"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
		"POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1048576\r\n\r\n",
	} {
		t.Run(strings.Fields(request)[0], func(t *testing.T) {
			started := make(chan struct{})
			ended := make(chan struct{})
			fixture := startProxy(t, Config{Dialer: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				close(ended)
				return nil, ctx.Err()
			})})
			conn := connectProxy(t, fixture)
			_, _ = io.WriteString(conn, request)
			<-started
			closed := make(chan struct{})
			go func() { _ = fixture.server.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Close did not cancel pending dial")
			}
			select {
			case <-ended:
			default:
				t.Fatal("Close returned while dial was still running")
			}
		})
	}
}

func TestNewServerValidation(t *testing.T) {
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") })
	for _, config := range []Config{
		{}, {Dialer: dialer, Username: "user"}, {Dialer: dialer, Password: []byte("secret")},
		{Dialer: dialer, Username: "user:colon", Password: []byte("secret")},
		{Dialer: dialer, Username: "user", Password: bytes.Repeat([]byte("x"), 256)},
		{Dialer: dialer, HandshakeTimeout: -time.Second},
	} {
		if _, err := NewServer(config); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	server, err := NewServer(Config{Dialer: dialer})
	if err != nil || server.timeout != DefaultHandshakeTimeout {
		t.Fatalf("default timeout = %v, %v", server, err)
	}
	_ = server.Close()
}

func TestReadHTTPHeaderBoundary(t *testing.T) {
	// A line ending exactly after the reader's buffer must not look like an
	// empty line; the actual blank line can be followed by pipelined body bytes.
	line := "X-Padding: " + strings.Repeat("x", 4096-len("X-Padding: ")) + "\r\n"
	header := "POST http://example.test/ HTTP/1.1\r\n" + line + "Content-Length: 4\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(header + "body"))
	actual, err := readHTTPHeader(reader)
	if err != nil || string(actual) != header {
		t.Fatalf("header bytes = %d, want %d: %v", len(actual), len(header), err)
	}
	readExact(t, reader, []byte("body"))
}
