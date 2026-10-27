package localproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type acceptFailure struct{ temporary bool }

func (acceptFailure) Error() string       { return "public test accept failure" }
func (acceptFailure) Timeout() bool       { return false }
func (err acceptFailure) Temporary() bool { return err.temporary }

type injectedAcceptListener struct {
	net.Listener
	failNext atomic.Bool
	failed   chan struct{}
}

func (listener *injectedAcceptListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if listener.failNext.Swap(false) {
		_ = conn.Close()
		listener.failed <- struct{}{}
		return nil, fmt.Errorf("wrapped public failure: %w", acceptFailure{temporary: true})
	}
	return conn, nil
}

func TestTemporaryAcceptFailurePreservesConnectionsAndRecovers(t *testing.T) {
	server, err := NewServer(Config{Dialer: targetDialer(echoTarget(t, false), nil)})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	injected := &injectedAcceptListener{Listener: listener, failed: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, injected) }()
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
	fixture := proxyFixture{server: server, addr: listener.Addr().String()}
	connect := func() *net.TCPConn {
		client := connectProxy(t, fixture)
		_, _ = client.Write([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80})
		readExact(t, client, []byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		return client
	}
	active := connect()
	_, _ = active.Write([]byte("before"))
	readExact(t, active, []byte("before"))
	injected.failNext.Store(true)
	trigger, err := net.DialTimeout("tcp", fixture.addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = trigger.Close()
	select {
	case <-injected.failed:
	case <-time.After(time.Second):
		t.Fatal("temporary accept error was not injected")
	}
	_, _ = active.Write([]byte("still-active"))
	readExact(t, active, []byte("still-active"))
	recovered := connect()
	_, _ = recovered.Write([]byte("accepted-after-error"))
	readExact(t, recovered, []byte("accepted-after-error"))
}

type failingAcceptListener struct {
	err    error
	calls  chan time.Time
	closed chan struct{}
	once   sync.Once
}

func (listener *failingAcceptListener) Accept() (net.Conn, error) {
	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	default:
	}
	select {
	case listener.calls <- time.Now():
	default:
	}
	return nil, listener.err
}
func (listener *failingAcceptListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}
func (*failingAcceptListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestTemporaryAcceptBackoffIsCancelableWithoutBusyLoop(t *testing.T) {
	for _, stop := range []string{"context", "close"} {
		t.Run(stop, func(t *testing.T) {
			server, err := NewServer(Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected dial") })})
			if err != nil {
				t.Fatal(err)
			}
			listener := &failingAcceptListener{err: acceptFailure{temporary: true}, calls: make(chan time.Time, 32), closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer server.Close()
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx, listener) }()
			var first, last time.Time
			for index := 0; index < 8; index++ {
				select {
				case stamp := <-listener.calls:
					if index == 0 {
						first = stamp
					}
					last = stamp
				case err := <-done:
					t.Fatalf("temporary error stopped Serve: %v", err)
				case <-time.After(3 * time.Second):
					t.Fatal("accept retry did not occur")
				}
			}
			if last.Sub(first) < 300*time.Millisecond {
				t.Fatal("temporary errors retried without backoff")
			}
			if stop == "context" {
				cancel()
			} else if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("canceled retry returned failure: %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("stop waited for the remaining accept backoff")
			}
		})
	}
}

func TestPermanentAcceptFailureStillStopsServe(t *testing.T) {
	server, err := NewServer(Config{Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected dial") })})
	if err != nil {
		t.Fatal(err)
	}
	listener := &failingAcceptListener{err: acceptFailure{}, calls: make(chan time.Time, 4), closed: make(chan struct{})}
	if err := server.Serve(context.Background(), listener); err == nil {
		t.Fatal("permanent accept failure was ignored")
	}
	if len(listener.calls) != 1 {
		t.Fatal("permanent accept failure was retried")
	}
}
