package localproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type responseBodyWaitConn struct {
	net.Conn
	headerBytes int
	readBytes   int
	bodyRead    chan struct{}
	once        sync.Once
	closed      chan struct{}
	closeOnce   sync.Once
}

func (conn *responseBodyWaitConn) Close() error {
	err := conn.Conn.Close()
	if conn.closed != nil {
		conn.closeOnce.Do(func() { close(conn.closed) })
	}
	return err
}

func (conn *responseBodyWaitConn) Read(data []byte) (int, error) {
	if conn.readBytes >= conn.headerBytes {
		conn.once.Do(func() { close(conn.bodyRead) })
	}
	n, err := conn.Conn.Read(data)
	conn.readBytes += n
	return n, err
}

func waitHTTPConnectionsClosed(t *testing.T, server *Server) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		server.mu.Lock()
		remaining := len(server.conns)
		server.mu.Unlock()
		if remaining == 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("HTTP request retained %d connections after client cancellation", remaining)
		case <-ticker.C:
		}
	}
}

func TestHTTPClientEOFClosesStalledResponse(t *testing.T) {
	// Ordinary HTTP uses a framed request body, so client EOF is
	// cancellation even after CloseWrite. SOCKS/CONNECT retain tunnel half-close.
	requests := []struct{ name, method, headers, body string }{
		{"no-body", "GET", "", ""},
		{"fixed-body", "POST", "Content-Length: 5\r\n", "first"},
		{"chunked-body", "POST", "Transfer-Encoding: chunked\r\n", "5\r\nfirst\r\n0\r\n\r\n"},
	}
	for _, requestMode := range requests {
		for _, closeMode := range []string{"close", "close-write"} {
			t.Run(requestMode.name+"/"+closeMode, func(t *testing.T) {
				const header = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
				bodyRead := make(chan struct{})
				upstreamClosed := make(chan struct{})
				fixture := startProxy(t, Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
					upstream, origin := net.Pipe()
					go func() {
						defer close(upstreamClosed)
						defer origin.Close()
						request, err := http.ReadRequest(bufio.NewReader(origin))
						if err != nil {
							return
						}
						if _, err := io.Copy(io.Discard, request.Body); err != nil {
							return
						}
						_ = request.Body.Close()
						if _, err := io.WriteString(origin, header); err != nil {
							return
						}
						// Do not send the advertised body. Observe the proxy's close.
						_, _ = io.Copy(io.Discard, origin)
					}()
					return &responseBodyWaitConn{Conn: upstream, headerBytes: len(header), bodyRead: bodyRead}, nil
				})})
				client := connectProxy(t, fixture)
				_, _ = fmt.Fprintf(client, "%s http://example.test/stalled HTTP/1.1\r\nHost: example.test\r\n%s\r\n%s", requestMode.method, requestMode.headers, requestMode.body)
				select {
				case <-bodyRead:
				case <-time.After(time.Second):
					t.Fatal("proxy did not start reading the stalled response body")
				}
				if closeMode == "close-write" {
					if err := client.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				} else {
					_ = client.Close()
				}
				select {
				case <-upstreamClosed:
				case <-time.After(time.Second):
					t.Fatal("client EOF did not close the stalled upstream")
				}
				waitHTTPConnectionsClosed(t, fixture.server)
			})
		}
	}
}

func TestHTTPClientCloseCancelsIncompleteUpload(t *testing.T) {
	prefixReceived := make(chan struct{})
	upstreamClosed := make(chan struct{})
	fixture := startProxy(t, Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		upstream, origin := net.Pipe()
		go func() {
			defer close(upstreamClosed)
			defer origin.Close()
			request, err := http.ReadRequest(bufio.NewReader(origin))
			if err != nil {
				return
			}
			if _, err := io.ReadFull(request.Body, make([]byte, 5)); err != nil {
				return
			}
			close(prefixReceived)
			_, _ = io.Copy(io.Discard, request.Body)
		}()
		return upstream, nil
	})})
	client := connectProxy(t, fixture)
	_, _ = io.WriteString(client, "POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1024\r\n\r\nfirst")
	select {
	case <-prefixReceived:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive the upload prefix")
	}
	_ = client.Close()
	select {
	case <-upstreamClosed:
	case <-time.After(time.Second):
		t.Fatal("canceled upload did not close upstream")
	}
	waitHTTPConnectionsClosed(t, fixture.server)
}

func TestHTTPClientCloseCancelsStalledEarlyResponse(t *testing.T) {
	const header = "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 100\r\n\r\n"
	bodyRead := make(chan struct{})
	upstreamClosed := make(chan struct{})
	fixture := startProxy(t, Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		upstream, origin := net.Pipe()
		go func() {
			defer close(upstreamClosed)
			defer origin.Close()
			request, err := http.ReadRequest(bufio.NewReader(origin))
			if err != nil {
				return
			}
			if _, err := io.ReadFull(request.Body, make([]byte, 5)); err != nil {
				return
			}
			if _, err := io.WriteString(origin, header); err != nil {
				return
			}
			// The origin rejects the upload, then leaves its response unfinished.
			_, _ = io.Copy(io.Discard, origin)
		}()
		return &responseBodyWaitConn{Conn: upstream, headerBytes: len(header), bodyRead: bodyRead}, nil
	})})
	client := connectProxy(t, fixture)
	_, _ = io.WriteString(client, "POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1024\r\n\r\nfirst")
	select {
	case <-bodyRead:
	case <-time.After(time.Second):
		t.Fatal("proxy did not start reading the stalled early response body")
	}
	_ = client.Close()
	select {
	case <-upstreamClosed:
	case <-time.After(time.Second):
		t.Fatal("client close left the early response upstream open")
	}
	waitHTTPConnectionsClosed(t, fixture.server)
}

func TestHTTPClientCloseCancelsBackpressuredEarlyResponse(t *testing.T) {
	const header = "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 100\r\n\r\n"
	bodyRead := make(chan struct{})
	upstreamClosed := make(chan struct{})
	fixture := startProxy(t, Config{HandshakeTimeout: 100 * time.Millisecond, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		upstream, origin := net.Pipe()
		go func() {
			defer origin.Close()
			if _, err := http.ReadRequest(bufio.NewReader(origin)); err != nil {
				return
			}
			if _, err := io.WriteString(origin, header); err != nil {
				return
			}
			// Keep the upload backpressured and the final response body open.
			<-upstreamClosed
		}()
		return &responseBodyWaitConn{Conn: upstream, headerBytes: len(header), bodyRead: bodyRead, closed: upstreamClosed}, nil
	})})
	client := connectProxy(t, fixture)
	_, _ = io.WriteString(client, "POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1048576\r\n\r\n"+strings.Repeat("x", 64<<10))
	select {
	case <-bodyRead:
	case <-time.After(time.Second):
		t.Fatal("proxy did not start reading the stalled early response body")
	}
	_ = client.Close()
	select {
	case <-upstreamClosed:
	case <-time.After(time.Second):
		t.Fatal("backpressured upload left the early response upstream open")
	}
	waitHTTPConnectionsClosed(t, fixture.server)
}

func TestHTTPClientCloseCancelsDetachedDial(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan struct{})
	fixture := startProxy(t, Config{Dialer: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(ended)
		return nil, ctx.Err()
	})})
	client := connectProxy(t, fixture)
	_, _ = io.WriteString(client, "GET http://example.test/pending HTTP/1.1\r\nHost: example.test\r\n\r\n")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream dial did not start")
	}
	_ = client.Close()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("client close did not cancel the detached upstream dial")
	}
	waitHTTPConnectionsClosed(t, fixture.server)
}

func TestHTTPDisconnectMonitorWaitsForFullUpload(t *testing.T) {
	const prefix = "first"
	const suffix = "\r\nGET http://body.test/ HTTP/1.1\r\n\r\nstill-body"
	prefixReceived := make(chan struct{})
	checked := make(chan error, 1)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		first := make([]byte, len(prefix))
		_, err := io.ReadFull(request.Body, first)
		if err == nil && string(first) != prefix {
			err = fmt.Errorf("incorrect upload prefix")
		}
		close(prefixReceived)
		rest, readErr := io.ReadAll(request.Body)
		if err == nil {
			err = readErr
		}
		if err == nil && string(rest) != suffix {
			err = fmt.Errorf("disconnect monitor consumed the request body")
		}
		checked <- err
		_, _ = io.WriteString(writer, "complete")
	}))
	defer target.Close()
	const writeTimeout = 200 * time.Millisecond
	fixture := startProxy(t, Config{HandshakeTimeout: writeTimeout, Dialer: targetDialer(strings.TrimPrefix(target.URL, "http://"), nil)})
	client := connectProxy(t, fixture)
	_, _ = fmt.Fprintf(client, "POST http://example.test/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n%s", len(prefix)+len(suffix), prefix)
	select {
	case <-prefixReceived:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stream the upload prefix")
	}
	// Pauses between writes do not make a progressing upload exceed a total
	// duration limit: only a write actively blocked at the origin is bounded.
	time.Sleep(writeTimeout + 50*time.Millisecond)
	_, _ = io.WriteString(client, suffix)
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(output) != "complete" {
		t.Fatalf("upload response = %d %q, %v", response.StatusCode, output, err)
	}
	if err := <-checked; err != nil {
		t.Fatal(err)
	}
	waitHTTPConnectionsClosed(t, fixture.server)
}
