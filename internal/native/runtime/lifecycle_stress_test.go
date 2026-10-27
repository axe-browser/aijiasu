package runtime

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/fvproxy"
)

func TestConcurrentControlStopRepeatedlyReleasesEveryCandidate(t *testing.T) {
	const iterations = 20
	const clients = 8
	for iteration := range iterations {
		config := testConfig(t)
		var blockAuthentication atomic.Bool
		entered := make(chan struct{})
		var enteredOnce sync.Once
		var enginesMu sync.Mutex
		var engines []*fakeEngine
		deps := testDeps(func(fvproxy.Config) (proxyEngine, error) {
			engine := &fakeEngine{auth: func(ctx context.Context) error {
				if blockAuthentication.Load() {
					enteredOnce.Do(func() { close(entered) })
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}}
			enginesMu.Lock()
			engines = append(engines, engine)
			enginesMu.Unlock()
			return engine, nil
		})
		ready, cancel, done := startRuntime(t, config, deps)
		blockAuthentication.Store(true)
		ctx, cancelClients := context.WithTimeout(context.Background(), 5*time.Second)
		var clientsDone sync.WaitGroup
		start := make(chan struct{})
		for client := range clients {
			clientsDone.Go(func() {
				<-start
				commands := []Request{{Command: "status"}, {Command: "switch", NodeID: "b"}, {Command: "disconnect"}, {Command: "connect", NodeID: "a"}}
				for request := range 12 {
					// Shutdown may close or remove the socket while these calls are
					// queued. Their bounded return, rather than success, is required.
					_, _ = Call(ctx, config.Directory, commands[(client+request)%len(commands)])
				}
			})
		}
		close(start)
		select {
		case <-entered:
		case <-ctx.Done():
			cancelClients()
			cancel()
			clientsDone.Wait()
			t.Fatalf("iteration %d did not reach an active candidate", iteration)
		}
		control, cancelControl := context.WithTimeout(context.Background(), 2*time.Second)
		stopped, stopErr := Call(control, config.Directory, Request{Command: "stop"})
		cancelControl()
		clientsDone.Wait()
		cancelClients()
		runErr := await(t, done)
		cancel()
		if stopErr != nil || runErr != nil || stopped.Running || stopped.Connected {
			t.Fatalf("iteration %d did not complete concurrent shutdown: stop=%v run=%v", iteration, stopErr, runErr)
		}
		enginesMu.Lock()
		for _, engine := range engines {
			if !engine.isClosed() {
				enginesMu.Unlock()
				t.Fatalf("iteration %d retained an authenticated or pending candidate", iteration)
			}
		}
		enginesMu.Unlock()
		assertStartupResourcesClosed(t, config, ready.ListenAddress)
	}
}
