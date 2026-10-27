package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"aijiasu-native/internal/native/fvproxy"
)

type retryRPCListener struct {
	net.Listener
	calls    atomic.Int32
	failures int32
	failure  error
	called   chan struct{}
}

func (listener *retryRPCListener) Accept() (net.Conn, error) {
	call := listener.calls.Add(1)
	if listener.called != nil {
		select {
		case listener.called <- struct{}{}:
		default:
		}
	}
	if listener.failures < 0 || call <= listener.failures {
		return nil, listener.failure
	}
	return listener.Listener.Accept()
}

func temporaryRPCAcceptError() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
}

func TestRPCListenerRecoversAfterTemporaryAcceptFailure(t *testing.T) {
	config := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, err := newManager(ctx, config, testDeps(func(fvproxy.Config) (proxyEngine, error) { return &fakeEngine{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.close()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	listener := &retryRPCListener{Listener: base, failures: 2, failure: temporaryRPCAcceptError()}
	server := newRPCServer(ctx, listener, manager, cancel, make(chan struct{}))
	done := make(chan error, 1)
	go func() { done <- server.serve() }()
	conn, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "{\"command\":\"status\"}\n"); err != nil {
		t.Fatal(err)
	}
	data, err := readLine(conn, maxRPCResponseBytes)
	var answer reply
	if err != nil || json.Unmarshal(data, &answer) != nil || !answer.Status.Running || answer.Error != "" {
		t.Fatal("RPC did not recover after temporary listener failures")
	}
	if listener.calls.Load() < 3 {
		t.Fatal("RPC did not retry its temporary failures")
	}
	_ = conn.Close()
	cancel()
	_ = listener.Close()
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	server.closeOrdinaryConnections()
	server.workers.Wait()
}

func TestRPCListenerRetryBackoffIsCancelableAndPermanentErrorsExit(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		t.Run(map[bool]string{false: "permanent", true: "temporary"}[temporary], func(t *testing.T) {
			base, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("permanent constructed listener failure")
			if temporary {
				failure = temporaryRPCAcceptError()
			}
			listener := &retryRPCListener{Listener: base, failures: -1, failure: failure, called: make(chan struct{}, 1)}
			server := newRPCServer(ctx, listener, nil, cancel, make(chan struct{}))
			done := make(chan error, 1)
			go func() { done <- server.serve() }()
			<-listener.called
			if temporary {
				cancel()
			}
			err = await(t, done)
			if temporary && err != nil || !temporary && err == nil {
				t.Fatalf("listener recovery policy returned %v", err)
			}
			if !temporary && listener.calls.Load() != 1 {
				t.Fatal("permanent listener failure retried")
			}
		})
	}
}
