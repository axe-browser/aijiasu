package fvproxy

import (
	"context"
	"testing"
	"time"
)

func TestKeepaliveFailureBudgetRestartsAfterReauthentication(t *testing.T) {
	server := newReferenceServer(t, "bad pong")
	engine := referenceEngine(t, server)
	for session := 0; session < 2; session++ {
		if err := engine.Authenticate(context.Background()); err != nil {
			t.Fatal(err)
		}
		before := server.pings.Load()
		engine.mu.Lock()
		engine.lastAlive = time.Now().Add(-6 * time.Second)
		engine.mu.Unlock()
		waitFor(t, func() bool { return server.pings.Load() >= before+2 || !engine.Status().Authenticated })
		if !engine.Status().Authenticated {
			t.Fatal("new session inherited the previous keepalive failure count")
		}
		waitFor(t, func() bool { return !engine.Status().Authenticated })
		if server.pings.Load() != before+3 {
			t.Fatal("session did not receive its own three-failure budget")
		}
	}
}

func TestOldGenerationCannotInvalidateReauthenticatedSession(t *testing.T) {
	server := newReferenceServer(t, "")
	engine := referenceEngine(t, server)
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	oldGeneration := engine.generation
	engine.mu.Unlock()
	engine.failSession(oldGeneration, "public-test first session failure")
	if err := engine.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.failSession(oldGeneration, "stale failure must not affect the new session")
	if status := engine.Status(); !status.Authenticated || status.LastError != "" {
		t.Fatal("stale keepalive failure invalidated a new session")
	}
	conn, err := engine.DialContext(context.Background(), "tcp", "target.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
