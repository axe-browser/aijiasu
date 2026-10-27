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
	"strconv"
	"strings"
	"sync"
	"time"
)

var errHeaderTooLarge = errors.New("proxy request header exceeds size limit")

func (server *Server) serveHTTP(client *trackedConn, reader *bufio.Reader, deadline time.Time) {
	header, err := readHTTPHeader(reader)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errHeaderTooLarge) {
			status = http.StatusRequestHeaderFieldsTooLarge
		}
		writeHTTPError(client, status)
		return
	}
	requestReader := bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader))
	request, err := http.ReadRequest(requestReader)
	if err != nil {
		writeHTTPError(client, http.StatusBadRequest)
		return
	}
	// Do not drain a rejected body: it may be unbounded or waiting for Continue.
	if request.ProtoMajor != 1 || request.ProtoMinor > 1 {
		writeHTTPError(client, http.StatusHTTPVersionNotSupported)
		return
	}
	if !server.httpAuthentication(request.Header) {
		writeHTTPError(client, http.StatusProxyAuthRequired)
		return
	}
	if request.Method == http.MethodConnect {
		server.httpConnect(client, requestReader, request, deadline)
		return
	}
	server.httpForward(client, requestReader, request, deadline)
}

func readHTTPHeader(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, 4096)
	continued := false
	for {
		line, err := reader.ReadSlice('\n')
		if len(header)+len(line) > MaxHeaderBytes {
			return nil, errHeaderTooLarge
		}
		header = append(header, line...)
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				continued = true
				continue
			}
			return nil, errors.New("incomplete proxy request header")
		}
		if !continued && (bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n"))) {
			return header, nil
		}
		continued = false
	}
}

func (server *Server) httpAuthentication(header http.Header) bool {
	values := header.Values("Proxy-Authorization")
	header.Del("Proxy-Authorization")
	if !server.authenticate {
		return true
	}
	if len(values) != 1 {
		return false
	}
	scheme, encoded, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	credentials, err := base64.StdEncoding.DecodeString(encoded)
	defer clear(credentials)
	if err != nil {
		return false
	}
	separator := bytes.IndexByte(credentials, ':')
	if separator < 1 {
		return false
	}
	return server.validCredentials(credentials[:separator], credentials[separator+1:])
}

func (server *Server) httpConnect(client *trackedConn, reader *bufio.Reader, request *http.Request, deadline time.Time) {
	address, ok := targetAddress(request.RequestURI, "")
	if !ok || request.URL.User != nil || request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		writeHTTPError(client, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(server.ctx, deadline)
	defer cancel()
	upstream, err := server.dial(ctx, address)
	if err != nil {
		writeHTTPError(client, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	relay(client, upstream, reader)
}

func (server *Server) httpForward(client *trackedConn, reader *bufio.Reader, request *http.Request, deadline time.Time) {
	if !strings.EqualFold(request.URL.Scheme, "http") || request.URL.User != nil || request.URL.Opaque != "" ||
		request.URL.Fragment != "" || request.URL.Host == "" || request.Header.Get("Upgrade") != "" {
		writeHTTPError(client, http.StatusBadRequest)
		return
	}
	address, ok := targetAddress(request.URL.Host, "80")
	if !ok {
		writeHTTPError(client, http.StatusBadRequest)
		return
	}
	if expect := request.Header.Get("Expect"); expect != "" {
		if !strings.EqualFold(expect, "100-continue") {
			writeHTTPError(client, http.StatusExpectationFailed)
			return
		}
		if _, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return
		}
	}
	operation, cancel := context.WithCancel(server.ctx)
	defer cancel()
	bodyRead := make(chan struct{})
	outgoing := request.Clone(operation)
	outgoing.RequestURI = ""
	outgoing.URL.Scheme = "http"
	// Transport must not drain an incomplete client upload when a dial fails or
	// the origin responds early. The owning handler closes the client socket.
	if request.Body != nil && request.Body != http.NoBody {
		outgoing.Body = &forwardBody{Reader: request.Body, remaining: request.ContentLength, done: bodyRead, cancel: cancel}
	} else {
		close(bodyRead)
	}
	outgoing.Host = request.URL.Host
	outgoing.Close = true
	outgoing.Trailer = nil
	stripHopHeaders(outgoing.Header)
	outgoing.Header.Del("Expect")
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		ResponseHeaderTimeout:  server.timeout,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialContext, cancelDial := context.WithDeadline(ctx, deadline)
			// Transport can detach a dial from the request's cancellation.
			stop := context.AfterFunc(operation, cancelDial)
			defer stop()
			defer cancelDial()
			upstream, err := server.dial(dialContext, address)
			if err != nil {
				return nil, err
			}
			return &httpWriteConn{Conn: upstream, timeout: server.timeout, cancel: cancel}, nil
		},
	}
	defer transport.CloseIdleConnections()
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	stopMonitor := monitorHTTPClient(operation, cancel, client, reader, bodyRead)
	defer stopMonitor()
	response, err := transport.RoundTrip(outgoing)
	if err != nil {
		writeHTTPError(client, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		writeHTTPError(client, http.StatusBadGateway)
		return
	}
	forwarded := *response
	forwarded.Header = response.Header.Clone()
	forwarded.Trailer = nil
	forwarded.Close = true
	stripHopHeaders(forwarded.Header)
	_ = forwarded.Write(client)
}

type httpWriteConn struct {
	net.Conn
	timeout time.Duration
	cancel  context.CancelFunc
}

func (conn *httpWriteConn) Write(data []byte) (int, error) {
	// An origin can send a response while refusing more upload data. In that
	// case the transport's writer cannot observe the client's later EOF, so a
	// stalled write must also cancel the response. Refreshing each write allows
	// streaming uploads to last longer than this per-write timeout (default 10s).
	if err := conn.SetWriteDeadline(time.Now().Add(conn.timeout)); err != nil {
		conn.cancel()
		return 0, err
	}
	n, err := conn.Conn.Write(data)
	if err != nil {
		conn.cancel()
	}
	return n, err
}

type forwardBody struct {
	io.Reader
	remaining int64
	done      chan struct{}
	cancel    context.CancelFunc
	once      sync.Once
}

func (body *forwardBody) Read(buffer []byte) (int, error) {
	n, err := body.Reader.Read(buffer)
	if body.remaining > 0 {
		body.remaining -= int64(n)
	}
	if err == io.EOF || body.remaining == 0 {
		body.once.Do(func() { close(body.done) })
	} else if err != nil {
		body.cancel()
	}
	return n, err
}

func (*forwardBody) Close() error { return nil }

func monitorHTTPClient(ctx context.Context, cancel context.CancelFunc, client *trackedConn, reader *bufio.Reader, bodyRead <-chan struct{}) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			return
		case <-bodyRead:
		}
		// The transport alone reads the upload. Only after its exact body boundary
		// may this connection's read side be used to observe client disconnects.
		// Like a normal HTTP server, EOF cancels an ordinary HTTP request; unlike
		// SOCKS/CONNECT, write-half-close is not an end-of-request signal here.
		var extra [1]byte
		for {
			if _, err := reader.Read(extra[:]); err != nil {
				cancel()
				return
			}
		}
	}()
	return func() {
		cancel()
		_ = client.SetReadDeadline(time.Now())
		<-done
	}
}

func stripHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, field := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(field))
		}
	}
	for _, field := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(field)
	}
}

func targetAddress(authority, defaultPort string) (string, bool) {
	if strings.ContainsAny(authority, "/\\@?#\r\n\x00\t ") {
		return "", false
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if defaultPort == "" {
			return "", false
		}
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			host, port = authority[1:len(authority)-1], defaultPort
			if net.ParseIP(host) == nil {
				return "", false
			}
		} else {
			if strings.Contains(authority, ":") {
				return "", false
			}
			host, port = authority, defaultPort
		}
	}
	if !validHost(host) || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
		return "", false
	}
	if port == "" {
		return "", false
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return "", false
	}
	return net.JoinHostPort(host, strconv.FormatUint(value, 10)), true
}

func validHost(host string) bool {
	if host == "" || len(host) > 255 || strings.ContainsAny(host, "/\\@?#[]\r\n\x00\t ") {
		return false
	}
	for _, char := range host {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func writeHTTPError(writer io.Writer, status int) {
	text := http.StatusText(status)
	authenticate := ""
	if status == http.StatusProxyAuthRequired {
		authenticate = "Proxy-Authenticate: Basic realm=\"Local proxy\"\r\n"
	}
	_, _ = fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n%s\r\n%s\n", status, text, len(text)+1, authenticate, text)
}
