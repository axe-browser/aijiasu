package nodemgr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
)

type probeConn struct {
	closed atomic.Int32
}

func (conn *probeConn) Read([]byte) (int, error)    { return 0, errors.New("probe must not read") }
func (conn *probeConn) Write([]byte) (int, error)   { return 0, errors.New("probe must not write") }
func (conn *probeConn) Close() error                { conn.closed.Add(1); return nil }
func (*probeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*probeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*probeConn) SetDeadline(time.Time) error      { return nil }
func (*probeConn) SetReadDeadline(time.Time) error  { return nil }
func (*probeConn) SetWriteDeadline(time.Time) error { return nil }

func probeFixtureNodes(count int) []clientapi.Node {
	nodes := make([]clientapi.Node, count)
	for index := range nodes {
		nodes[index] = clientapi.Node{ID: fmt.Sprintf("node-%d", index), Host: "example.test", TCPPort: 1000 + index}
	}
	return nodes
}

func TestProbeTCPClosesWithoutSendingApplicationData(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan error, defaultProbeAttempts)
	go func() {
		for range defaultProbeAttempts {
			conn, err := listener.Accept()
			if err != nil {
				observed <- err
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var payload [1]byte
			count, err := conn.Read(payload[:])
			_ = conn.Close()
			if count != 0 || !errors.Is(err, io.EOF) {
				observed <- errors.New("probe sent application bytes or did not close immediately")
			} else {
				observed <- nil
			}
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	nodes := []clientapi.Node{{ID: "loopback", Host: "127.0.0.1", TCPPort: address.Port}}
	results, err := Probe(context.Background(), nodes, ProbeConfig{})
	if err != nil || len(results) != 1 || !results[0].Reachable || results[0].Attempts != 2 || results[0].Successes != 2 || results[0].Milliseconds < minimumLatencyMS || results[0].CheckedAt.IsZero() || results[0].Error != "" {
		t.Fatalf("TCP probe = %#v, %v", results, err)
	}
	for range defaultProbeAttempts {
		select {
		case err := <-observed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("fixture did not observe closed TCP connection")
		}
	}
}

func TestProbeUsesMedianOfSuccessfulConnectionTimes(t *testing.T) {
	for _, test := range []struct {
		name      string
		durations []time.Duration
		failures  map[int]bool
		want      float64
		successes int
	}{
		{"odd-successes", []time.Duration{80 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond}, nil, 30, 3},
		{"even-successes", []time.Duration{50 * time.Millisecond, 10 * time.Millisecond}, nil, 30, 2},
		{"failed-sample-excluded", []time.Duration{80 * time.Millisecond, time.Second, 20 * time.Millisecond}, map[int]bool{1: true}, 50, 2},
		{"zero-clock-resolution", []time.Duration{0, 0}, nil, minimumLatencyMS, 2},
		{"clock-moved-backwards", []time.Duration{-time.Millisecond}, nil, minimumLatencyMS, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 10, 26, 1, 2, 3, 0, time.FixedZone("fixture", 3600))
			attempt := 0
			var connections []*probeConn
			results, err := Probe(context.Background(), probeFixtureNodes(1), ProbeConfig{
				Attempts: len(test.durations), Concurrency: 1,
				Now: func() time.Time { return now },
				DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "tcp" || address != "example.test:1000" {
						t.Fatalf("unexpected dial: %q %q", network, address)
					}
					index := attempt
					now = now.Add(test.durations[index])
					attempt++
					conn := &probeConn{}
					connections = append(connections, conn)
					if test.failures[index] {
						// Even nonstandard dialers returning both must be closed.
						return conn, errors.New("PUBLIC_FIXTURE_PRIVATE_ERROR")
					}
					return conn, nil
				},
			})
			if err != nil || len(results) != 1 || results[0].Milliseconds != test.want || results[0].Successes != test.successes || results[0].Attempts != len(test.durations) || !results[0].Reachable || results[0].Error != "" || results[0].CheckedAt.Location() != time.UTC {
				t.Fatalf("median = %#v, %v", results, err)
			}
			for _, conn := range connections {
				if conn.closed.Load() != 1 {
					t.Fatal("dialed connection was not closed exactly once")
				}
			}
		})
	}
}

func TestProbeAllFailuresAreUnreachableAndHaveSafeErrors(t *testing.T) {
	for _, nilConnection := range []bool{false, true} {
		t.Run(fmt.Sprint(nilConnection), func(t *testing.T) {
			results, err := Probe(context.Background(), probeFixtureNodes(1), ProbeConfig{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					if nilConnection {
						return nil, nil
					}
					return nil, errors.New("PRIVATE_FIXTURE_USERNAME_PASSWORD_HOST_URL")
				},
			})
			if err != nil || len(results) != 1 || results[0].Reachable || results[0].Successes != 0 || results[0].Attempts != 2 || results[0].Milliseconds != 0 || results[0].Error != "TCP connection failed" {
				t.Fatalf("unreachable result = %#v, %v", results, err)
			}
		})
	}
}

func TestProbeAttemptTimeoutIsNotOverallFailure(t *testing.T) {
	started := time.Now()
	var ended atomic.Int32
	results, err := Probe(context.Background(), probeFixtureNodes(1), ProbeConfig{
		Timeout: 15 * time.Millisecond, Budget: time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			ended.Add(1)
			return nil, ctx.Err()
		},
	})
	if err != nil || len(results) != 1 || results[0].Reachable || results[0].Attempts != 2 || ended.Load() != 2 || time.Since(started) > time.Second {
		t.Fatalf("per-attempt timeout = %#v, ended=%d, %v", results, ended.Load(), err)
	}
}

func TestProbeBoundsWorkersAndPreservesInputOrder(t *testing.T) {
	const concurrency = 3
	nodes := probeFixtureNodes(12)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, len(nodes))
	release := make(chan struct{})
	var active, peak, closed atomic.Int32
	type probeResult struct {
		latencies []Latency
		err       error
	}
	done := make(chan probeResult, 1)
	go func() {
		results, err := Probe(ctx, nodes, ProbeConfig{
			Attempts: 1, Concurrency: concurrency,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				count := active.Add(1)
				defer active.Add(-1)
				for count > peak.Load() {
					previous := peak.Load()
					if count <= previous || peak.CompareAndSwap(previous, count) {
						break
					}
				}
				started <- address
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				closed.Add(1)
				return &probeConn{}, nil
			},
		})
		done <- probeResult{results, err}
	}()
	for range concurrency {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("expected concurrent probes did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("probe exceeded configured concurrency")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case result := <-done:
		if result.err != nil || len(result.latencies) != len(nodes) || peak.Load() != concurrency || active.Load() != 0 || closed.Load() != int32(len(nodes)) {
			t.Fatalf("worker bounds: count=%d peak=%d active=%d, %v", len(result.latencies), peak.Load(), active.Load(), result.err)
		}
		for index, latency := range result.latencies {
			if latency.ID != nodes[index].ID || latency.Port != nodes[index].TCPPort {
				t.Fatalf("result order changed at %d: %#v", index, latency)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("worker pool did not finish")
	}
}

func TestProbeCancellationReturnsPartialResultsAndJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts, ended atomic.Int32
	results, err := Probe(ctx, probeFixtureNodes(5), ProbeConfig{
		Attempts: 2, Concurrency: 1,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			attempt := attempts.Add(1)
			if attempt == 1 {
				return &probeConn{}, nil
			}
			cancel()
			<-ctx.Done()
			ended.Add(1)
			return nil, ctx.Err()
		},
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrProbeBudgetExceeded) || len(results) != 1 || results[0].ID != "node-0" || !results[0].Reachable || results[0].Attempts != 2 || results[0].Successes != 1 || results[0].Milliseconds < minimumLatencyMS || attempts.Load() != 2 || ended.Load() != 1 {
		t.Fatalf("canceled result = %#v, attempts=%d ended=%d, %v", results, attempts.Load(), ended.Load(), err)
	}
}

func TestProbeBudgetAndCallerDeadlineAreDistinct(t *testing.T) {
	for _, callerDeadline := range []bool{false, true} {
		t.Run(fmt.Sprint(callerDeadline), func(t *testing.T) {
			ctx := context.Background()
			budget := 100 * time.Millisecond
			if callerDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				budget = time.Second
			}
			var active atomic.Int32
			results, err := Probe(ctx, probeFixtureNodes(5), ProbeConfig{
				Timeout: time.Second, Budget: budget, Concurrency: 2,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					active.Add(1)
					defer active.Add(-1)
					<-ctx.Done()
					return nil, ctx.Err()
				},
			})
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrProbeBudgetExceeded) == callerDeadline || len(results) != 2 || active.Load() != 0 {
				t.Fatalf("deadline result = %#v, active=%d, %v", results, active.Load(), err)
			}
			for index, result := range results {
				if result.ID != fmt.Sprintf("node-%d", index) || result.Attempts != 1 || result.Reachable || result.Error != "node probe interrupted" {
					t.Fatalf("partial result = %#v", result)
				}
			}
		})
	}
}

func TestProbeValidatesAllNodesBeforeDialing(t *testing.T) {
	for _, test := range []struct {
		name string
		node clientapi.Node
	}{
		{"empty-id", clientapi.Node{Host: "example.test", TCPPort: 443}},
		{"control-id", clientapi.Node{ID: "bad\nID", Host: "example.test", TCPPort: 443}},
		{"bidi-id", clientapi.Node{ID: "bad\u202eID", Host: "example.test", TCPPort: 443}},
		{"zero-port", clientapi.Node{ID: "bad", Host: "example.test"}},
		{"large-port", clientapi.Node{ID: "bad", Host: "example.test", TCPPort: 65536}},
		{"empty-host", clientapi.Node{ID: "bad", TCPPort: 443}},
		{"url-host", clientapi.Node{ID: "bad", Host: "https://example.test", TCPPort: 443}},
		{"userinfo-host", clientapi.Node{ID: "bad", Host: "user:secret@example.test", TCPPort: 443}},
		{"host-with-port", clientapi.Node{ID: "bad", Host: "example.test:443", TCPPort: 443}},
		{"bracketed-ipv6", clientapi.Node{ID: "bad", Host: "[::1]", TCPPort: 443}},
		{"path-host", clientapi.Node{ID: "bad", Host: "example.test/path", TCPPort: 443}},
		{"newline-host", clientapi.Node{ID: "bad", Host: "example.test\r\nsecret", TCPPort: 443}},
		{"empty-label", clientapi.Node{ID: "bad", Host: "example..test", TCPPort: 443}},
		{"long-label", clientapi.Node{ID: "bad", Host: strings.Repeat("x", 64) + ".test", TCPPort: 443}},
	} {
		t.Run(test.name, func(t *testing.T) {
			nodes := append(probeFixtureNodes(1), test.node)
			results, err := Probe(context.Background(), nodes, ProbeConfig{DialContext: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("validation failure dialed a target")
				return nil, nil
			}})
			if err == nil || len(results) != 0 || strings.Contains(err.Error(), "example.test") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe validation = %#v, %v", results, err)
			}
		})
	}
	for _, nodes := range [][]clientapi.Node{
		append(probeFixtureNodes(1), probeFixtureNodes(1)...),
		make([]clientapi.Node, maxProbeNodes+1),
	} {
		if _, err := Probe(context.Background(), nodes, ProbeConfig{DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("invalid batch dialed")
			return nil, nil
		}}); err == nil {
			t.Fatal("invalid node batch accepted")
		}
	}
}

func TestProbeIPv4IPv6AndDomainAddresses(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "node.example.test", "node.example.test."} {
		t.Run(host, func(t *testing.T) {
			var addresses []string
			node := clientapi.Node{ID: "node", Host: host, TCPPort: 443}
			results, err := Probe(context.Background(), []clientapi.Node{node}, ProbeConfig{
				Attempts: 1,
				DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "tcp" {
						t.Fatal("probe attempted non-TCP traffic")
					}
					addresses = append(addresses, address)
					return &probeConn{}, nil
				},
			})
			if err != nil || len(results) != 1 || results[0].Host != host || !reflect.DeepEqual(addresses, []string{net.JoinHostPort(host, "443")}) {
				t.Fatalf("address = %v, results %#v, %v", addresses, results, err)
			}
		})
	}
}

func TestProbeInvalidLimitsEmptyAndPreCanceled(t *testing.T) {
	for _, config := range []ProbeConfig{
		{Timeout: -time.Second}, {Budget: -time.Second}, {Attempts: -1}, {Concurrency: -1},
		{Attempts: maxProbeAttempts + 1}, {Concurrency: maxProbeConcurrency + 1},
	} {
		config.DialContext = func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("invalid limits dialed")
			return nil, nil
		}
		if _, err := Probe(context.Background(), probeFixtureNodes(1), config); err == nil {
			t.Fatal("invalid probe config accepted")
		}
	}
	results, err := Probe(context.Background(), nil, ProbeConfig{})
	if err != nil || results == nil || len(results) != 0 {
		t.Fatalf("empty input = %#v, %v", results, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err = Probe(ctx, probeFixtureNodes(1), ProbeConfig{DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("pre-canceled probe dialed")
		return nil, nil
	}})
	if !errors.Is(err, context.Canceled) || len(results) != 0 {
		t.Fatalf("pre-canceled = %#v, %v", results, err)
	}
}

func TestProbeClockInjectionIsSerialized(t *testing.T) {
	// This deliberately non-atomic clock is safe because Probe serializes it.
	clock := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	var connectionsMu sync.Mutex
	var connections []*probeConn
	results, err := Probe(context.Background(), probeFixtureNodes(24), ProbeConfig{
		Concurrency: 8,
		Now:         func() time.Time { clock = clock.Add(time.Microsecond); return clock },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			conn := &probeConn{}
			connectionsMu.Lock()
			connections = append(connections, conn)
			connectionsMu.Unlock()
			return conn, nil
		},
	})
	if err != nil || len(results) != 24 {
		t.Fatalf("concurrent clock = %d results, %v", len(results), err)
	}
	for _, conn := range connections {
		if conn.closed.Load() != 1 {
			t.Fatal("concurrent probe leaked a connection")
		}
	}
}
