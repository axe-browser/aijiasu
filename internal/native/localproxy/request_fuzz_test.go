package localproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

func FuzzHTTPHeaderBoundary(f *testing.F) {
	for _, data := range [][]byte{
		[]byte("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\nbody"),
		[]byte("CONNECT example.test:443 HTTP/1.1\nHost: example.test\n\ntunnel"),
		[]byte("POST http://example.test/ HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody"),
		[]byte("GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 4096) + "\r\n\r\ntrailing"),
		[]byte("\r\n"),
	} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		bufferSize := 16
		if len(data) > 0 {
			bufferSize += int(data[0])
		}
		reader := bufio.NewReaderSize(bytes.NewReader(data), bufferSize)
		header, err := readHTTPHeader(reader)
		if err != nil {
			return
		}
		if len(header) > MaxHeaderBytes || !bytes.HasPrefix(data, header) {
			t.Fatal("HTTP framing crossed its header bound")
		}
		remaining, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(remaining, data[len(header):]) {
			t.Fatal("HTTP header parsing consumed or changed body/tunnel bytes")
		}
	})
}

func FuzzProxyTargetBoundaries(f *testing.F) {
	for _, data := range [][]byte{[]byte("example.test:443"), []byte("[::1]:443"), {1, 127, 0, 0, 1}, {3, 12, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't'}, {4, 0, 0, 0, 0}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, defaultPort := range []string{"", "80"} {
			address, ok := targetAddress(string(data), defaultPort)
			if !ok {
				continue
			}
			host, port, err := net.SplitHostPort(address)
			parsedPort, parseErr := strconv.ParseUint(port, 10, 16)
			if err != nil || parseErr != nil || parsedPort == 0 || !validHost(host) {
				t.Fatal("accepted HTTP target cannot be safely split into host and port")
			}
		}
		if len(data) == 0 {
			return
		}
		host, ok := readSOCKSHost(bytes.NewReader(data[1:]), data[0])
		if !ok {
			return
		}
		if !validHost(host) || data[0] == 3 && strings.ContainsAny(host, ":[]") {
			t.Fatal("SOCKS host parser accepted unsafe address bytes")
		}
		if data[0] != 3 && net.ParseIP(host) == nil {
			t.Fatal("SOCKS IP address did not decode to an IP")
		}
	})
}
