package localproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentTunnelTrafficReleasesAllConnections(t *testing.T) {
	fixture := startProxy(t, Config{Dialer: targetDialer(echoTarget(t, false), nil)})
	const rounds, concurrent, payloadBytes = 4, 24, 64 << 10
	for round := range rounds {
		results := make(chan error, concurrent)
		var workers sync.WaitGroup
		for worker := range concurrent {
			workers.Go(func() {
				payload := bytes.Repeat([]byte{byte(round), byte(worker), 0, 0xff}, payloadBytes/4)
				results <- exerciseConcurrentTunnel(fixture.addr, worker%2 == 0, payload)
			})
		}
		workers.Wait()
		for range concurrent {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		waitHTTPConnectionsClosed(t, fixture.server)
	}
	if err := fixture.server.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.server.mu.Lock()
	remaining := len(fixture.server.conns)
	fixture.server.mu.Unlock()
	if remaining != 0 {
		t.Fatal("concurrent traffic retained tracked connections after shutdown")
	}
}

func exerciseConcurrentTunnel(address string, httpConnect bool, payload []byte) error {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	if httpConnect {
		if _, err := io.WriteString(conn, "CONNECT public-fixture.invalid:443 HTTP/1.1\r\nHost: public-fixture.invalid:443\r\n\r\n"); err != nil {
			return err
		}
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200 ") {
			return fmt.Errorf("HTTP tunnel did not complete its handshake")
		}
		for line != "\r\n" {
			line, err = reader.ReadString('\n')
			if err != nil {
				return err
			}
		}
	} else {
		if _, err := conn.Write([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80}); err != nil {
			return err
		}
		var response [12]byte
		if _, err := io.ReadFull(reader, response[:]); err != nil || !bytes.Equal(response[:], []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
			return fmt.Errorf("SOCKS tunnel did not complete its handshake")
		}
	}
	written := make(chan error, 1)
	go func() {
		n, err := conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		written <- err
	}()
	got, readErr := io.ReadAll(reader)
	if err := <-written; err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("concurrent tunnel data was mixed or truncated")
	}
	return nil
}
