package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
)

const diagnosticSecret = "SYNTHETIC_PRIVATE_ACCOUNT_PASSWORD_TOKEN_RESPONSE"

func assertLoginDiagnostic(t *testing.T, stdout, stderr string, code string, status int) {
	t.Helper()
	if stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
		t.Fatal("failure must have empty stdout and exactly one stderr JSON line")
	}
	want := fmt.Sprintf(`{"schemaVersion":1,"command":"login","error":{"code":%q}}`+"\n", code)
	if status != 0 {
		want = fmt.Sprintf(`{"schemaVersion":1,"command":"login","error":{"code":%q,"http_status":%d}}`+"\n", code, status)
	}
	if stderr != want || strings.Contains(stderr, diagnosticSecret) {
		t.Fatalf("unexpected fixed diagnostic: %s", stderr)
	}
	var decoded map[string]json.RawMessage
	if json.Unmarshal([]byte(stderr), &decoded) != nil || len(decoded) != 3 {
		t.Fatal("diagnostic envelope contains unexpected fields")
	}
}

func TestLoginJSONDiagnosticsPreserveExitCodesAndNeverExposeCauses(t *testing.T) {
	for _, test := range []struct {
		name, code string
		err        error
		status     int
		exitCode   int
	}{
		{"auth", "auth_rejected", clientapi.ErrAuthRejected, 0, exitFailure},
		{"TLS", "tls_verification", clientapi.ErrTLSVerification, 0, exitFailure},
		{"timeout", "timeout", context.DeadlineExceeded, 0, exitFailure},
		{"DNS", "dns_failure", &net.DNSError{Name: diagnosticSecret, Err: diagnosticSecret}, 0, exitFailure},
		{"network", "network_failure", clientapi.ErrNetworkFailure, 0, exitFailure},
		{"HTTP", "http_status", &clientapi.HTTPStatusError{StatusCode: 401}, 401, exitFailure},
		{"response", "invalid_response", clientapi.ErrInvalidResponse, 0, exitFailure},
		{"unknown", "unknown", errors.New(diagnosticSecret), 0, exitFailure},
		{"canceled", "canceled", context.Canceled, 0, exitCancelled},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := testDependencies()
			dependencies.newClient = func(clientapi.Config) (loginClient, error) {
				return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
					return clientapi.Session{}, fmt.Errorf("%s: %w", diagnosticSecret, test.err)
				}), nil
			}
			saved := false
			dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
				saved = true
				return nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"login", "--error-format=json", "-u", diagnosticSecret, "--password-stdin"}, strings.NewReader(diagnosticSecret+"\n"), &stdout, &stderr, dependencies)
			if code != test.exitCode || saved {
				t.Fatal("diagnostic failure changed exit code or saved a failed login")
			}
			assertLoginDiagnostic(t, stdout.String(), stderr.String(), test.code, test.status)
		})
	}
}

func TestLoginErrorFormatDoesNotChangeSuccessOrTextMode(t *testing.T) {
	for _, extra := range [][]string{nil, {"--error-format=text"}, {"--error-format=json"}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"login", "-u", "public-account"}, extra...)
		if code := run(context.Background(), args, nil, &stdout, &stderr, testDependencies()); code != 0 || stdout.String() != "登录成功，会话已保存。\n" {
			t.Fatal("diagnostic mode changed successful login")
		}
		want := "密码: \n"
		if len(extra) > 0 && extra[0] == "--error-format=json" {
			want = ""
		}
		if stderr.String() != want {
			t.Fatal("diagnostic mode leaked a prompt or changed text prompt")
		}
	}
	for _, args := range [][]string{
		{"login", "--error-format=json", "--unsupported=" + diagnosticSecret},
		{"login", "--error-format=json"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, nil, &stdout, &stderr, cliDependencies{}); code != exitUsage {
			t.Fatal("invalid arguments did not keep exit 2")
		}
		assertLoginDiagnostic(t, stdout.String(), stderr.String(), "unknown", 0)
	}
}

func diagnosticHTTPClient(endpoint string, httpClient *http.Client) cliDependencies {
	dependencies := testDependencies()
	dependencies.newClient = func(config clientapi.Config) (loginClient, error) {
		config.Endpoint, config.HTTPClient = endpoint, httpClient
		config.CommonParameters = map[string]string{"v": "test", "_site": "ajs", "_lang": "en", "_m": "test", "_os_ver": "test", "_os_dev": "test", "_os_dim": "test", "_uid": "testUID"}
		return clientapi.NewClient(config)
	}
	return dependencies
}

func runHTTPDiagnostic(t *testing.T, endpoint string, httpClient *http.Client, want string, status int) {
	t.Helper()
	dependencies := diagnosticHTTPClient(endpoint, httpClient)
	dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
		t.Fatal("failed request saved a session")
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"login", "--error-format=json", "-u", diagnosticSecret, "--password-stdin"}, strings.NewReader(diagnosticSecret+"\n"), &stdout, &stderr, dependencies)
	if code != exitFailure {
		t.Fatalf("network fixture returned exit %d", code)
	}
	assertLoginDiagnostic(t, stdout.String(), stderr.String(), want, status)
}

func TestLoginDiagnosticLocalHTTPAndTLS(t *testing.T) {
	for _, status := range []int{307, 401, 403, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if status == 307 {
					writer.Header().Set("Location", "https://private-redirect.invalid/?token="+diagnosticSecret)
				}
				writer.WriteHeader(status)
				io.WriteString(writer, diagnosticSecret)
			}))
			defer server.Close()
			runHTTPDiagnostic(t, server.URL, server.Client(), "http_status", status)
		})
	}
	for _, test := range []struct{ body, code string }{
		{`{"Login":{"AuthResult":"DENIED","AuthMessage":"` + diagnosticSecret + `"}}`, "auth_rejected"},
		{diagnosticSecret, "invalid_response"},
	} {
		t.Run(test.code, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				io.WriteString(writer, test.body)
			}))
			defer server.Close()
			runHTTPDiagnostic(t, server.URL, server.Client(), test.code, 0)
		})
	}
	t.Run("TLS certificate", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS sent credentials") }))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		defer server.Close()
		runHTTPDiagnostic(t, server.URL, &http.Client{Timeout: time.Second}, "tls_verification", 0)
	})
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			io.Copy(io.Discard, request.Body)
			<-request.Context().Done()
		}))
		defer server.Close()
		client := server.Client()
		client.Timeout = 50 * time.Millisecond
		runHTTPDiagnostic(t, server.URL, client, "timeout", 0)
	})
	t.Run("network EOF", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			connection, _, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
		}))
		defer server.Close()
		runHTTPDiagnostic(t, server.URL, server.Client(), "network_failure", 0)
	})
	t.Run("connection refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		runHTTPDiagnostic(t, "https://"+address, &http.Client{Timeout: time.Second}, "connection_refused", 0)
	})
}

func TestLoginDiagnosticLocalDNSNXDOMAIN(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	defer func() { server.Close(); <-finished }()
	go func() {
		defer close(finished)
		query := make([]byte, 4096)
		for {
			n, address, err := server.ReadFrom(query)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			answer := append([]byte(nil), query[:n]...)
			binary.BigEndian.PutUint16(answer[2:4], 0x8183)
			clear(answer[6:12])
			server.WriteTo(answer, address)
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", server.LocalAddr().String())
	}}
	dialer := &net.Dialer{Resolver: resolver}
	transport := &http.Transport{DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	runHTTPDiagnostic(t, "https://synthetic-login.invalid", &http.Client{Transport: transport, Timeout: time.Second}, "dns_failure", 0)
}
