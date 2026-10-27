package clientapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func priorSession() Session {
	return Session{Username: testUsername, LoginToken: testToken, AuthenticatedAt: time.Unix(100, 0).UTC(), ServiceUsername: "service-user", Nodes: []Node{{ID: "1", Host: "old.example.test", TCPPort: 443}}, SyncVersion: map[string]string{"Login": "1", "Servers": "2"}}
}

func TestRefreshExactTokenRequestAndIncrementalSections(t *testing.T) {
	const expectedBody = "_client_login=constructed-local-test-token&_lang=en&_m=linux&_os_dev=x86_64&_os_dim=lid%3d0123456789abcdef0123456789abcdef&_os_ver=test%20OS&_site=ajs&_sync[Login]=1&_sync[Servers]=2&_uid=0123456789abcdef0123456789abcdef&cmd=ClientApiLogin%2fLogin&username=user%2bname%40example.test&v=4.3.0.1"
	prior := priorSession()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != expectedBody || r.Method != http.MethodPost || r.URL.Path != "/client.php" {
			t.Error("refresh request differs from fixed offline form fixture")
		}
		// Public constructed vector, independently generated with Python uint32
		// masking; it is not captured authentication traffic.
		if r.Header.Get("X-Timestamp") != "123456789" || r.Header.Get("X-Sig") != "2589e8a9abac26c1" {
			t.Error("refresh did not sign its exact token body")
		}
		if strings.Contains(string(body), "password") || !r.Close {
			t.Error("refresh leaked password field or omitted connection-close policy")
		}
		io.WriteString(w, `{"SyncVersion":{"Login":1,"Servers":"2"}}`)
	}))
	defer server.Close()
	client := newTestClient(t, testConfig(server.URL+"/client.php", server.Client()))
	got, err := client.Refresh(context.Background(), prior)
	if err != nil || calls.Load() != 1 || !reflect.DeepEqual(got, prior) {
		t.Fatalf("incremental refresh = %+v, %v", got, err)
	}
	got.Nodes[0].Host = "changed"
	got.SyncVersion["Servers"] = "changed"
	if prior.Nodes[0].Host != "old.example.test" || prior.SyncVersion["Servers"] != "2" {
		t.Fatal("refresh output aliases prior session")
	}
}

func TestLoginFullSyncAndRefreshChangedSections(t *testing.T) {
	const reply = `{"SyncVersion":{"Login":3,"Servers":4},"Login":{"AuthResult":"OK","LoginToken":"new-token","UserName":"canonical-user","ExpireTime":1800000000},"Servers":{"b":{"id":"2","tit":"B","svr":"b.example.test","par":{"fv":{"p":443}}},"a":{"id":1,"tit":"A","sts":"unknown","svr":"a.example.test","par":{"fv":{"u":10000,"p":"80"}}}}}`
	for _, refresh := range []bool{false, true} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, reply) }))
		client := newTestClient(t, testConfig(server.URL, server.Client()))
		var got Session
		var err error
		if refresh {
			got, err = client.Refresh(context.Background(), priorSession())
		} else {
			got, err = client.Login(context.Background(), testUsername, []byte(testPassword))
		}
		server.Close()
		if err != nil || got.LoginToken != "new-token" || got.ServiceUsername != "canonical-user" || len(got.Nodes) != 2 || got.Nodes[0].ID != "1" || got.Nodes[0].TCPPort != 80 || got.Nodes[0].UDPPort != 10000 || got.SyncVersion["Servers"] != "4" {
			t.Fatalf("full synchronization returned wrong public state: %+v, %v", got, err)
		}
	}
}

func TestRefreshInvalidResponsesDoNotMutatePrior(t *testing.T) {
	for _, reply := range []string{
		`{"SyncVersion":{"Login":2,"Servers":2}}`,
		`{"SyncVersion":{"Login":1,"Servers":3}}`,
		`{"SyncVersion":{"Login":1,"Servers":3},"Servers":null}`,
		`{"SyncVersion":{"Login":1,"Servers":2},"Login":{"AuthResult":"DENIED","AuthMessage":"` + testToken + `"}}`,
		`{"SyncVersion":{"Login":1,"Servers":2},"Servers":[{"id":{}}]}`,
		`{"SyncVersion":{"Login":[],"Servers":2}}`,
		`{"SyncVersion":{"bad&field":1}}`,
		`{"Login":{"AuthResult":"OK","LoginToken":"new-token"}}`,
	} {
		prior := priorSession()
		before, _ := json.Marshal(prior)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, reply) }))
		client := newTestClient(t, testConfig(server.URL, server.Client()))
		got, err := client.Refresh(context.Background(), prior)
		server.Close()
		after, _ := json.Marshal(prior)
		if err == nil || !reflect.DeepEqual(got, Session{}) || string(before) != string(after) {
			t.Fatalf("invalid refresh returned or changed state: %v", err)
		}
		assertSafeError(t, err)
	}
}

func TestRefreshOldMinimalSessionAndTLSVerification(t *testing.T) {
	minimal := Session{Username: testUsername, LoginToken: testToken}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "token") {
			t.Error("token used in URL")
		}
		io.WriteString(w, validReply)
	}))
	defer server.Close()
	client := newTestClient(t, testConfig(server.URL, server.Client()))
	if _, err := client.Refresh(context.Background(), minimal); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	untrusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	untrusted.StartTLS()
	defer untrusted.Close()
	client = newTestClient(t, testConfig(untrusted.URL, &http.Client{}))
	_, err := client.Refresh(context.Background(), minimal)
	var certificateError *tls.CertificateVerificationError
	if !errors.Is(err, ErrTLSVerification) || !errors.As(err, &certificateError) || calls.Load() != 0 {
		t.Fatal("refresh bypassed strict TLS verification")
	}
	assertSafeError(t, err)
}

func TestRefreshRejectsUnsafePriorWithoutRequest(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, testConfig("https://example.test", &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected request")
	})}))
	for _, change := range []func(*Session){
		func(s *Session) { s.Username = "" }, func(s *Session) { s.LoginToken = "" },
		func(s *Session) { s.SyncVersion["bad]field"] = "1" },
		func(s *Session) { s.Nodes[0].TCPPort = 65536 },
	} {
		prior := priorSession()
		change(&prior)
		if _, err := client.Refresh(context.Background(), prior); err == nil {
			t.Fatal("invalid prior session accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid prior session sent authentication")
	}
}
