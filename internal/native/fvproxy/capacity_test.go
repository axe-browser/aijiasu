package fvproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func occupyDataBudget(t *testing.T, engine *Engine) []net.Conn {
	t.Helper()
	peers := make([]net.Conn, 0, maxEngineConnections)
	engine.mu.Lock()
	for range maxEngineConnections {
		local, peer := net.Pipe()
		engine.connections[&streamConn{Conn: local, engine: engine}] = struct{}{}
		peers = append(peers, peer)
	}
	engine.mu.Unlock()
	t.Cleanup(func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	})
	return peers
}

func TestEngineKeepaliveAtFullDataBudget(t *testing.T) {
	for _, mode := range []string{"", "bad pong"} {
		t.Run(mode, func(t *testing.T) {
			server := newReferenceServer(t, mode)
			engine := referenceEngine(t, server)
			if err := engine.Authenticate(context.Background()); err != nil {
				t.Fatal(err)
			}
			peers := occupyDataBudget(t, engine)
			if _, err := engine.DialContext(context.Background(), "tcp", "target.invalid:443"); !errors.Is(err, ErrConnectionLimit) {
				t.Fatalf("full data budget accepted another stream: %v", err)
			}
			if server.requests.Load() != 1 {
				t.Fatal("rejected data request contacted the server")
			}
			engine.mu.Lock()
			engine.lastAlive = time.Now().Add(-6 * time.Second)
			previousAlive := engine.lastAlive
			engine.mu.Unlock()
			if mode == "bad pong" {
				waitFor(t, func() bool {
					status := engine.Status()
					return !status.Authenticated && status.ActiveConnections == 0
				})
				if server.pings.Load() != 3 || engine.Status().ActiveConnections != 0 {
					t.Fatal("full data budget suppressed remote keepalive failures")
				}
				_ = peers[0].SetReadDeadline(time.Now().Add(time.Second))
				var data [1]byte
				if _, err := peers[0].Read(data[:]); err != io.EOF {
					t.Fatalf("invalidated session retained data stream: %v", err)
				}
				return
			}
			waitFor(t, func() bool {
				engine.mu.Lock()
				defer engine.mu.Unlock()
				return engine.lastAlive.After(previousAlive)
			})
			status := engine.Status()
			if server.pings.Load() == 0 || !status.Authenticated || status.ActiveConnections != maxEngineConnections || status.LastError != "" {
				t.Fatalf("full data budget interrupted healthy session: %+v", status)
			}
			_ = peers[0].SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			var data [1]byte
			_, err := peers[0].Read(data[:])
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("healthy keepalive closed data stream: %v", err)
			}
		})
	}
}

func TestEngineControlBudgetIncludesPendingAndDialing(t *testing.T) {
	for _, blockDial := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "dialing"}[blockDial], func(t *testing.T) {
			server := newReferenceServer(t, "")
			config := referenceConfig(server)
			var calls atomic.Int32
			started := make(chan struct{})
			config.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				if calls.Add(1) == 1 && blockDial {
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				local, peer := net.Pipe()
				t.Cleanup(func() { _ = peer.Close() })
				return local, nil
			}
			engine, err := NewEngine(config)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var conn net.Conn
			var stop func() bool
			finished := make(chan error, 1)
			if blockDial {
				go func() { _, _, err := engine.openPending(ctx, controlConnection); finished <- err }()
				<-started
			} else {
				conn, stop, err = engine.openPending(ctx, controlConnection)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := engine.openPending(context.Background(), controlConnection); !errors.Is(err, ErrConnectionLimit) {
				t.Fatalf("control budget allowed a second connection: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("rejected control request attempted another dial")
			}
			if blockDial {
				cancel()
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("control dial cancellation: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("canceled control dial retained its slot")
				}
			} else {
				stop()
				engine.removePending(conn)
				_ = conn.Close()
			}
			conn, stop, err = engine.openPending(context.Background(), controlConnection)
			if err != nil {
				t.Fatalf("completed control operation retained its slot: %v", err)
			}
			stop()
			engine.removePending(conn)
			_ = conn.Close()
		})
	}
}
