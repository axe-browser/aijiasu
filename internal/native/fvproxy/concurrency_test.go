package fvproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestConcurrentEncryptedStreamsReleaseCapacity(t *testing.T) {
	stopTargets := make(chan struct{})
	var targetsDone chan struct{}
	// Keep draining the independent reference server until its own cleanup has
	// joined every handler, including on a failed assertion below.
	t.Cleanup(func() {
		if targetsDone != nil {
			close(stopTargets)
			<-targetsDone
		}
	})
	server := newReferenceServer(t, "")
	targetsDone = make(chan struct{})
	go func() {
		defer close(targetsDone)
		for {
			select {
			case <-server.targets:
			case <-stopTargets:
				return
			}
		}
	}()
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	const rounds, concurrent, payloadBytes = 4, 24, 64 << 10
	for round := range rounds {
		results := make(chan error, concurrent)
		var workers sync.WaitGroup
		for worker := range concurrent {
			workers.Go(func() {
				payload := bytes.Repeat([]byte{byte(round), byte(worker), 0, 0xff}, payloadBytes/4)
				results <- exerciseEncryptedStream(engine, payload)
			})
		}
		workers.Wait()
		for range concurrent {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		if status := engine.Status(); !status.Authenticated || status.ActiveConnections != 0 {
			t.Fatal("concurrent streams invalidated authentication or retained capacity")
		}
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	pending, active, dialing := len(engine.pending), len(engine.connections), engine.dialing
	engine.mu.Unlock()
	if pending != 0 || active != 0 || dialing != [connectionKindCount]int{} {
		t.Fatal("engine shutdown retained pending, active, or dialing connections")
	}
}

func exerciseEncryptedStream(engine *Engine, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := engine.DialContext(ctx, "tcp", "public-fixture.invalid:443")
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() {
		n, err := conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		written <- err
	}()
	got, readErr := io.ReadAll(conn)
	if err := <-written; err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("concurrent stream ciphers mixed or truncated application data")
	}
	return nil
}
