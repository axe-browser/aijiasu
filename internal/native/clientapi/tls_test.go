package clientapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// All certificates and keys below are generated in memory for loopback tests.
// The leaf deliberately has CN localhost and no SAN to exercise explicit pin
// identity independently of CA or hostname validation.
func pinTestServer(t *testing.T, notBefore, notAfter time.Time, maxVersion uint16, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: maxVersion, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	digest := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	return server, hex.EncodeToString(digest[:])
}

func changedPin(pin string) string {
	if pin[0] == '0' {
		return "1" + pin[1:]
	}
	return "0" + pin[1:]
}

func TestTLSPinDefaultAndExplicitPolicies(t *testing.T) {
	var calls atomic.Int32
	server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, validReply) }))
	client := newTestClient(t, testConfig(server.URL, &http.Client{}))
	_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if !errors.Is(err, ErrTLSVerification) || calls.Load() != 0 {
		t.Fatal("default TLS policy trusted the test certificate or sent credentials")
	}
	config := testConfig(server.URL, &http.Client{})
	config.TLSSPKISHA256 = strings.ToUpper(pin)
	client = newTestClient(t, config)
	if _, err := client.Login(context.Background(), testUsername, []byte(testPassword)); err != nil || calls.Load() != 1 {
		t.Fatalf("explicit correct SPKI pin did not authenticate the endpoint: %v", err)
	}
	config.TLSSPKISHA256 = changedPin(pin)
	client = newTestClient(t, config)
	_, err = client.Login(context.Background(), testUsername, []byte(testPassword))
	if !errors.Is(err, ErrTLSVerification) || !errors.Is(err, ErrTLSPinMismatch) || calls.Load() != 1 {
		t.Fatal("wrong pin did not abort before HTTP")
	}
	assertSafeError(t, err)
	if strings.Contains(err.Error(), config.TLSSPKISHA256) {
		t.Fatal("TLS error contains a raw pin input")
	}
}

func TestTLSPinRejectsCertificateTimeOutsideCurrentWindow(t *testing.T) {
	for _, future := range []bool{false, true} {
		var calls atomic.Int32
		before, after := time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		if future {
			before, after = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
		}
		server, pin := pinTestServer(t, before, after, 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, validReply) }))
		config := testConfig(server.URL, &http.Client{})
		config.TLSSPKISHA256 = pin
		client := newTestClient(t, config)
		_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
		if !errors.Is(err, ErrTLSVerification) || calls.Load() != 0 {
			t.Fatal("matching pin bypassed certificate time validity")
		}
		assertSafeError(t, err)
	}
}

func TestTLSPinDoesNotFallBackToValidCA(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, validReply) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer server.Close()
	trusted := server.Client()
	response, err := trusted.Get(server.URL)
	if err != nil {
		t.Fatal("local CA trust fixture did not verify")
	}
	_ = response.Body.Close()
	calls.Store(0)
	digest := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	config := testConfig(server.URL, trusted)
	config.TLSSPKISHA256 = changedPin(hex.EncodeToString(digest[:]))
	client := newTestClient(t, config)
	_, err = client.Login(context.Background(), testUsername, []byte(testPassword))
	if !errors.Is(err, ErrTLSPinMismatch) || calls.Load() != 0 {
		t.Fatal("valid CA chain bypassed an explicit wrong pin")
	}
}

func TestTLSPinRejectsInvalidConfigurationAndBypassTransports(t *testing.T) {
	for _, pin := range []string{"short", strings.Repeat("z", 64), " " + strings.Repeat("a", 64), testPassword + testSeed} {
		config := testConfig("https://example.test/client.php", nil)
		config.TLSSPKISHA256 = pin
		_, err := NewClient(config)
		if err == nil || strings.Contains(err.Error(), pin) {
			t.Fatal("invalid pin was accepted or echoed")
		}
		assertSafeError(t, err)
	}
	for _, transport := range []http.RoundTripper{
		testRoundTripper(func(*http.Request) (*http.Response, error) { t.Fatal("custom transport must not run"); return nil, nil }),
		&http.Transport{DialTLS: func(string, string) (net.Conn, error) { t.Fatal("custom TLS dialer must not run"); return nil, nil }},
		&http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("custom TLS dialer must not run")
			return nil, nil
		}},
	} {
		config := testConfig("https://example.test/client.php", &http.Client{Transport: transport})
		config.TLSSPKISHA256 = strings.Repeat("a", 64)
		if _, err := NewClient(config); err == nil {
			t.Fatal("pinning accepted a transport that bypasses TLS configuration")
		}
	}
}

func TestTLSPinClonesClientTransportAndPreservesAdditionalRejections(t *testing.T) {
	var calls atomic.Int32
	server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, validReply) }))
	baseTLS := &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(2)}
	base := &http.Transport{TLSClientConfig: baseTLS}
	defer base.CloseIdleConnections()
	httpClient := &http.Client{Transport: base}
	config := testConfig(server.URL, httpClient)
	config.TLSSPKISHA256 = pin
	client := newTestClient(t, config)
	owned := client.httpClient.Transport.(*http.Transport)
	if owned == base || owned.TLSClientConfig == baseTLS || owned.TLSClientConfig.ClientSessionCache == baseTLS.ClientSessionCache || baseTLS.InsecureSkipVerify || baseTLS.VerifyConnection != nil || base.DisableKeepAlives || httpClient.CheckRedirect != nil {
		t.Fatal("pin policy mutated or reused caller-owned security state")
	}
	if _, err := client.Login(context.Background(), testUsername, []byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	if response, err := httpClient.Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("another client inherited pin mode")
	}
	if calls.Load() != 1 {
		t.Fatal("untrusted original client sent HTTP")
	}
	for _, peer := range []bool{false, true} {
		base := &http.Transport{TLSClientConfig: &tls.Config{}}
		privateError := errors.New(testPassword + testSeed + testToken)
		if peer {
			base.TLSClientConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return privateError }
		} else {
			base.TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error { return privateError }
		}
		config := testConfig(server.URL, &http.Client{Transport: base})
		config.TLSSPKISHA256 = pin
		client := newTestClient(t, config)
		_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
		if !errors.Is(err, ErrTLSVerification) || !errors.Is(err, privateError) || calls.Load() != 1 {
			t.Fatal("additional TLS verifier rejection was discarded")
		}
		assertSafeError(t, err)
		base.CloseIdleConnections()
	}
}

func TestTLSPinVerifyConnectionAlsoRejectsResumedSessions(t *testing.T) {
	var calls atomic.Int32
	server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), tls.VersionTLS12, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, validReply) }))
	var reject, resumed atomic.Bool
	base := &http.Transport{TLSClientConfig: &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(2), MaxVersion: tls.VersionTLS12}}
	defer base.CloseIdleConnections()
	base.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if state.DidResume {
			resumed.Store(true)
			if reject.Load() {
				return errors.New(testPassword + testToken)
			}
		}
		return nil
	}
	config := testConfig(server.URL, &http.Client{Transport: base})
	config.TLSSPKISHA256 = pin
	client := newTestClient(t, config)
	if _, err := client.Login(context.Background(), testUsername, []byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if !resumed.Load() || !errors.Is(err, ErrTLSVerification) || calls.Load() != 1 {
		t.Fatalf("resumed connection bypassed its verifier: resumed=%v error=%v", resumed.Load(), err)
	}
	assertSafeError(t, err)
}

func TestTLSPinDoesNotForwardAuthenticationOnRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1); io.WriteString(w, validReply) }))
	defer target.Close()
	server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	config := testConfig(server.URL, &http.Client{})
	config.TLSSPKISHA256 = pin
	client := newTestClient(t, config)
	_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if err == nil || !strings.Contains(err.Error(), "HTTP status 307") || targetCalls.Load() != 0 {
		t.Fatal("pinned endpoint forwarded authentication to a redirect target")
	}
	assertSafeError(t, err)
}
