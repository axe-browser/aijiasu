package clientapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClientUsesBundledTrustAndHonorsExplicitOverrides(t *testing.T) {
	anchor, err := hex.DecodeString(officialLoginSPKI)
	if err != nil || len(anchor) != sha256.Size {
		t.Fatal("release login trust anchor is missing or malformed")
	}
	for _, operation := range []string{"login", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			for _, policy := range []string{"bundled", "correct explicit", "wrong explicit", "malformed explicit"} {
				t.Run(policy, func(t *testing.T) {
					var calls atomic.Int32
					server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
						calls.Add(1)
						io.WriteString(writer, validReply)
					}))
					config := trustTestConfig(t, server.Listener.Addr().String())
					switch policy {
					case "correct explicit":
						config.TLSSPKISHA256 = pin
					case "wrong explicit":
						config.TLSSPKISHA256 = changedPin(pin)
					case "malformed explicit":
						config.TLSSPKISHA256 = "invalid"
					}
					client, err := NewClient(config)
					if policy == "malformed explicit" {
						if err == nil || calls.Load() != 0 {
							t.Fatal("malformed explicit trust fell back to the bundled anchor")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if operation == "login" {
						_, err = client.Login(context.Background(), testUsername, []byte(testPassword))
					} else {
						_, err = client.Refresh(context.Background(), Session{Username: testUsername, LoginToken: testToken})
					}
					if policy == "correct explicit" {
						if err != nil || calls.Load() != 1 {
							t.Fatalf("explicit trust did not override the release anchor: %v", err)
						}
					} else if !errors.Is(err, ErrTLSPinMismatch) || calls.Load() != 0 {
						t.Fatal("unexpected key was accepted or the bundled policy was not applied")
					}
				})
			}
		})
	}
}

func TestNewClientBundledTrustKeepsOtherEndpointCAPolicy(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		io.WriteString(writer, validReply)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(testConfig(server.URL, server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Login(context.Background(), testUsername, []byte(testPassword)); err != nil || calls.Load() != 1 {
		t.Fatalf("bundled login anchor changed another endpoint's CA policy: %v", err)
	}
}

func trustTestConfig(t *testing.T, address string) Config {
	t.Helper()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
		if network != "tcp" || requested != "login.ajs-app.com:443" {
			return nil, errors.New("unexpected test destination")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return testConfig(officialLoginEndpoint, &http.Client{Transport: transport, Timeout: 2 * time.Second})
}

func TestBundledLoginTrustIsEndpointScopedAndExplicitTrustWins(t *testing.T) {
	defaultPin, explicitPin := strings.Repeat("a", 64), strings.Repeat("b", 64)
	trust := loginTrust{endpoint: officialLoginEndpoint, spki: defaultPin}
	for _, endpoint := range []string{
		"https://login.ajs-app.com.evil.test/client.php", "https://login.ajs-app.com:443/client.php",
		"https://login.ajs-app.com:444/client.php", "https://login.ajs-app.com/other", "https://LOGIN.ajs-app.com/client.php",
		"http://login.ajs-app.com/client.php", "https://user@login.ajs-app.com/client.php",
		"https://login.ajs-app.com/client.php?", "https://login.ajs-app.com/client.php#",
		"https://login.ajs-app.com/client%2ephp", "https://127.0.0.1/client.php", "https://other.example.test/client.php",
	} {
		if trust.pin(endpoint, "") != "" {
			t.Fatalf("bundled trust escaped the exact endpoint scope: %s", endpoint)
		}
		if trust.pin(endpoint, explicitPin) != explicitPin {
			t.Fatal("explicit trust was silently replaced")
		}
	}
	if trust.pin(officialLoginEndpoint, "") != defaultPin || trust.pin(officialLoginEndpoint, explicitPin) != explicitPin {
		t.Fatal("official endpoint default or explicit precedence changed")
	}
	if (loginTrust{endpoint: officialLoginEndpoint}).pin(officialLoginEndpoint, "") != "" {
		t.Fatal("an empty unverified anchor changed the system TLS policy")
	}
}

func TestBundledLoginTrustAuthenticatesOnlyTheExpectedKeyAndKeepsExpiryChecks(t *testing.T) {
	for _, test := range []string{"correct default", "replacement certificate", "expired", "future", "wrong explicit", "correct explicit", "no anchor"} {
		t.Run(test, func(t *testing.T) {
			var calls atomic.Int32
			before, after := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
			if test == "expired" {
				before, after = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			} else if test == "future" {
				before, after = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
			}
			server, actualPin := pinTestServer(t, before, after, 0, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.Host != "login.ajs-app.com" {
					t.Error("fixture lost the original endpoint")
				}
				io.WriteString(writer, validReply)
			}))
			config := trustTestConfig(t, server.Listener.Addr().String())
			trust := loginTrust{endpoint: officialLoginEndpoint, spki: actualPin}
			if test == "replacement certificate" {
				_, previousPin := pinTestServer(t, before, after, 0, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("previous server should not receive a request")
				}))
				trust.spki = previousPin
			}
			if test == "correct explicit" {
				trust.spki = changedPin(actualPin)
			}
			if test == "wrong explicit" {
				config.TLSSPKISHA256 = changedPin(actualPin)
			}
			if test == "correct explicit" {
				config.TLSSPKISHA256 = actualPin
			}
			if test == "no anchor" {
				trust.spki = ""
			}
			client, err := newClient(config, trust)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), testUsername, []byte(testPassword))
			if test == "correct default" || test == "correct explicit" {
				if err != nil || calls.Load() != 1 {
					t.Fatalf("trusted fixture did not connect: %v", err)
				}
			} else if !errors.Is(err, ErrTLSVerification) || calls.Load() != 0 {
				t.Fatal("incorrect or expired trust sent authentication")
			}
			if err != nil && DiagnoseLoginError(err).Code != "tls_verification" {
				t.Fatal("trust failure changed the safe error protocol")
			}
		})
	}
}

func TestBundledLoginTrustDoesNotAffectOtherEndpoints(t *testing.T) {
	var calls atomic.Int32
	server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		io.WriteString(writer, validReply)
	}))
	config := testConfig(server.URL, &http.Client{Timeout: time.Second})
	client, err := newClient(config, loginTrust{endpoint: officialLoginEndpoint, spki: pin})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Login(context.Background(), testUsername, []byte(testPassword))
	if !errors.Is(err, ErrTLSVerification) || calls.Load() != 0 {
		t.Fatal("bundled trust accepted a certificate at another endpoint")
	}
}

func TestBundledLoginTrustAlsoAppliesToTokenSynchronization(t *testing.T) {
	var calls atomic.Int32
	server, pin := pinTestServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 0, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		io.WriteString(writer, validReply)
	}))
	client, err := newClient(trustTestConfig(t, server.Listener.Addr().String()), loginTrust{endpoint: officialLoginEndpoint, spki: pin})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(context.Background(), Session{Username: testUsername, LoginToken: testToken})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("synchronization did not use the same trust policy: %v", err)
	}
}
