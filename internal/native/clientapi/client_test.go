package clientapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testSeed     = "test-signing-seed-only"
	testUsername = "user+name@example.test"
	testPassword = "p a&ss=秘密"
	testToken    = "constructed-local-test-token"
	validReply   = `{"Login":{"AuthResult":"OK","LoginToken":"constructed-local-test-token"}}`
)

func testConfig(endpoint string, httpClient *http.Client) Config {
	return Config{
		Endpoint:    endpoint,
		SigningSeed: testSeed,
		CommonParameters: map[string]string{
			"v":       "4.3.0.1",
			"_site":   "ajs",
			"_lang":   "en",
			"_m":      "linux",
			"_os_ver": "test OS",
			"_os_dev": "x86_64",
			"_os_dim": "lid=0123456789abcdef0123456789abcdef",
			"_uid":    "0123456789abcdef0123456789abcdef",
		},
		HTTPClient:      httpClient,
		NowMilliseconds: func() (uint64, error) { return 123456789, nil },
	}
}

func newTestClient(t *testing.T, config Config) *Client {
	t.Helper()
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestLoginRequestAndSession(t *testing.T) {
	// Constructed offline fixture, not captured traffic. The signature was
	// independently calculated using Python integers with explicit uint32 masks.
	const expectedBody = "_lang=en&_m=linux&_os_dev=x86_64&_os_dim=lid%3d0123456789abcdef0123456789abcdef&_os_ver=test%20OS&_site=ajs&_uid=0123456789abcdef0123456789abcdef&cmd=ClientApiLogin%2fLogin&password=p%20a%26ss%3d%e7%a7%98%e5%af%86&username=user%2bname%40example.test&v=4.3.0.1"
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		if request.Method != http.MethodPost || request.URL.Path != "/client.php" {
			t.Errorf("unexpected method/path: %s %s", request.Method, request.URL.Path)
		}
		if string(body) != expectedBody {
			t.Errorf("body = %q, want fixed fixture", body)
		}
		for name, want := range map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "*/*",
			"X-Timestamp":  "123456789",
			"X-Sig":        "8a453cd6a3cfb180",
			"User-Agent":   "",
			"Expect":       "",
		} {
			if got := request.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		if !request.Close || request.ContentLength != int64(len(expectedBody)) {
			t.Errorf("Close = %v, ContentLength = %d", request.Close, request.ContentLength)
		}
		if _, exists := request.Header["Expect"]; exists {
			t.Error("request must omit the Expect header")
		}
		io.WriteString(writer, `{"Login":{"AuthResult":"OK","LoginToken":"constructed-local-test-token","ExpireTime":"1800000000"}}`)
	}))
	defer server.Close()
	client := newTestClient(t, testConfig(server.URL+"/client.php", server.Client()))
	before := time.Now()
	password := []byte(testPassword)
	session, err := client.Login(context.Background(), testUsername, password)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || session.Username != testUsername || session.LoginToken != testToken || session.ExpireTime != json.Number("1800000000") {
		t.Fatalf("unexpected session or request count: %+v, %d", session, calls.Load())
	}
	if session.AuthenticatedAt.Before(before) || session.AuthenticatedAt.After(time.Now()) {
		t.Fatal("authentication time is outside request interval")
	}
	if string(password) != testPassword {
		t.Fatal("Login modified the caller's password")
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &saved); err != nil || len(saved) != 4 {
		t.Fatalf("saved session has unexpected fields: %s, %v", encoded, err)
	}
	for _, name := range []string{"username", "login_token", "authenticated_at", "expire_time"} {
		if _, exists := saved[name]; !exists {
			t.Errorf("saved session is missing %s", name)
		}
	}
	if bytes.Contains(encoded, []byte(testPassword)) || bytes.Contains(encoded, []byte(testSeed)) {
		t.Fatal("saved session contains authentication input")
	}
}

func TestLoginResponseValidation(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		status     int
		wantError  error
		wantText   string
		wantExpiry json.Number
	}{
		{name: "valid token", body: validReply},
		{name: "number expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":1800000000}}`, wantExpiry: "1800000000"},
		{name: "numeric string expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":"1.8e9"}}`, wantExpiry: "1.8e9"},
		{name: "null expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":null}}`},
		{name: "authentication rejected", body: `{"Login":{"AuthResult":"DENIED","AuthMessage":"` + testPassword + testSeed + testToken + `"}}`, wantError: ErrAuthRejected},
		{name: "lowercase result rejected", body: `{"Login":{"AuthResult":"ok","LoginToken":"token"}}`, wantError: ErrAuthRejected},
		{name: "unknown root", body: `{"SomethingElse":"` + testPassword + `"}`, wantError: ErrInvalidResponse},
		{name: "wrong Login case", body: `{"login":{"AuthResult":"OK","LoginToken":"token"}}`, wantError: ErrInvalidResponse},
		{name: "wrong AuthResult case", body: `{"Login":{"authresult":"OK","LoginToken":"token"}}`, wantError: ErrInvalidResponse},
		{name: "wrong result type", body: `{"Login":{"AuthResult":true,"LoginToken":"token"}}`, wantError: ErrInvalidResponse},
		{name: "null login", body: `{"Login":null}`, wantError: ErrInvalidResponse},
		{name: "non JSON", body: testPassword + testSeed, wantError: ErrInvalidResponse},
		{name: "malformed JSON", body: `{"Login":` + testPassword + `}`, wantError: ErrInvalidResponse},
		{name: "leading whitespace", body: " " + validReply, wantError: ErrInvalidResponse},
		{name: "trailing whitespace", body: validReply + "\n", wantError: ErrInvalidResponse},
		{name: "array", body: `[]`, wantError: ErrInvalidResponse},
		{name: "missing token", body: `{"Login":{"AuthResult":"OK"}}`, wantText: "missing a nonempty login token"},
		{name: "empty token", body: `{"Login":{"AuthResult":"OK","LoginToken":""}}`, wantText: "missing a nonempty login token"},
		{name: "wrong token case", body: `{"Login":{"AuthResult":"OK","logintoken":"token"}}`, wantText: "missing a nonempty login token"},
		{name: "number token", body: `{"Login":{"AuthResult":"OK","LoginToken":123}}`, wantText: "missing a nonempty login token"},
		{name: "malformed expiry string", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":"` + testPassword + testSeed + `"}}`, wantText: "invalid expiry time"},
		{name: "empty expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":""}}`, wantText: "invalid expiry time"},
		{name: "non finite expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":"NaN"}}`, wantText: "invalid expiry time"},
		{name: "object expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":{}}}`, wantText: "invalid expiry time"},
		{name: "boolean expiry", body: `{"Login":{"AuthResult":"OK","LoginToken":"token","ExpireTime":true}}`, wantText: "invalid expiry time"},
		{name: "HTTP error", body: testPassword + testSeed + testToken, status: http.StatusUnauthorized, wantText: "HTTP status 401"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if test.status != 0 {
					writer.WriteHeader(test.status)
				}
				io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := newTestClient(t, testConfig(server.URL, server.Client()))
			session, err := client.Login(context.Background(), testUsername, []byte(testPassword))
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if strings.Contains(test.wantText, "missing a nonempty login token") || test.wantText == "invalid expiry time" {
				if !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("error = %v, want invalid response classification", err)
				}
			}
			if test.wantText != "" && (err == nil || !strings.Contains(err.Error(), test.wantText)) {
				t.Fatalf("error = %v, want text %q", err, test.wantText)
			}
			if test.wantError == nil && test.wantText == "" {
				if err != nil || session.ExpireTime != test.wantExpiry {
					t.Fatalf("expiry = %q, error = %v", session.ExpireTime, err)
				}
			} else if !reflect.DeepEqual(session, Session{}) {
				t.Fatal("failed login returned session data")
			}
			assertSafeError(t, err)
		})
	}
}

func TestLoginGzipAndResponseLimit(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, oversized := range []bool{false, true} {
			name := "plain"
			if compressed {
				name = "gzip"
			}
			if oversized {
				name += " oversized"
			}
			t.Run(name, func(t *testing.T) {
				body := validReply
				if oversized {
					body = `{"unused":"` + strings.Repeat("a", maxResponseBytes) + `"}`
				}
				server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					if compressed {
						if request.Header.Get("Accept-Encoding") != "gzip" {
							t.Error("transport did not request gzip")
						}
						writer.Header().Set("Content-Encoding", "gzip")
						encoder := gzip.NewWriter(writer)
						io.WriteString(encoder, body)
						encoder.Close()
						return
					}
					io.WriteString(writer, body)
				}))
				defer server.Close()
				client := newTestClient(t, testConfig(server.URL, server.Client()))
				session, err := client.Login(context.Background(), testUsername, []byte(testPassword))
				if oversized {
					if !errors.Is(err, ErrResponseTooLarge) {
						t.Fatalf("error = %v, want size limit", err)
					}
				} else if err != nil || session.LoginToken != testToken {
					t.Fatalf("gzip/plain response failed: %v", err)
				}
			})
		}
	}
}

func TestLoginRedirectNeverForwardsCredentials(t *testing.T) {
	var firstCalls, secondCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		secondCalls.Add(1)
		io.WriteString(writer, validReply)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		firstCalls.Add(1)
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	var callerRedirect atomic.Int32
	httpClient := server.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		callerRedirect.Add(1)
		return nil
	}
	client := newTestClient(t, testConfig(server.URL, httpClient))
	_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if err == nil || !strings.Contains(err.Error(), "HTTP status 307") {
		t.Fatalf("error = %v, want HTTP 307", err)
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 0 || callerRedirect.Load() != 0 {
		t.Fatalf("redirect request/callback counts = %d/%d/%d", firstCalls.Load(), secondCalls.Load(), callerRedirect.Load())
	}
	if httpClient.CheckRedirect == nil {
		t.Fatal("caller redirect policy was modified")
	}
	httpClient.CheckRedirect(nil, nil)
	if callerRedirect.Load() != 1 {
		t.Fatal("caller redirect policy was replaced")
	}
}

func TestLoginRejectsUntrustedTLSBeforeSendingAuthentication(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		io.WriteString(writer, validReply)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	// Deliberately use the normal trust store instead of server.Client(), which
	// would trust this local test certificate.
	client := newTestClient(t, testConfig(server.URL, &http.Client{}))
	session, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if !errors.Is(err, ErrTLSVerification) {
		t.Fatalf("error = %v, want TLS verification classification", err)
	}
	var certificateError *tls.CertificateVerificationError
	if !errors.As(err, &certificateError) || !errors.Is(err, certificateError) {
		t.Fatal("TLS verification error discarded its diagnostic cause")
	}
	if calls.Load() != 0 || !reflect.DeepEqual(session, Session{}) {
		t.Fatal("TLS verification failure sent authentication or returned session data")
	}
	assertSafeError(t, err)

	secretCause := &tls.CertificateVerificationError{Err: errors.New(testPassword + testSeed + testToken)}
	safeError := safeRequestError(context.Background(), secretCause)
	if !errors.Is(safeError, ErrTLSVerification) || !errors.Is(safeError, secretCause) {
		t.Fatal("TLS error lost its classification or original cause")
	}
	assertSafeError(t, safeError)
}

func TestLoginCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"canceled before request", "context deadline", "client timeout", "body deadline"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				io.Copy(io.Discard, request.Body)
				if mode == "body deadline" {
					writer.WriteHeader(http.StatusOK)
					writer.(http.Flusher).Flush()
				}
				<-request.Context().Done()
			}))
			defer server.Close()
			config := testConfig(server.URL, server.Client())
			ctx := context.Background()
			var cancel context.CancelFunc
			wantError := context.DeadlineExceeded
			if mode == "canceled before request" {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantError = context.Canceled
			} else if mode == "client timeout" {
				config.HTTPClient.Timeout = 100 * time.Millisecond
			} else {
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			client := newTestClient(t, config)
			_, err := client.Login(ctx, testUsername, []byte(testPassword))
			if !errors.Is(err, wantError) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, wantError)
			}
			if mode == "canceled before request" && calls.Load() != 0 {
				t.Fatal("canceled login sent a request")
			}
			assertSafeError(t, err)
		})
	}
}

func TestNewClientRejectsInvalidConfiguration(t *testing.T) {
	for _, endpoint := range []string{
		"http://example.test/client.php", "https:///client.php", "https://user:pass@example.test/client.php",
		"https://example.test/?token=secret", "https://example.test/?", "https://example.test/#fragment", "https://example.test/#", "://bad",
	} {
		config := testConfig(endpoint, nil)
		if _, err := NewClient(config); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
	for _, field := range []string{"cmd", "username", "password", "_client_login", "PASSWORD"} {
		config := testConfig("https://example.test/client.php", nil)
		config.CommonParameters[field] = testPassword
		if _, err := NewClient(config); err == nil {
			t.Errorf("accepted authentication common parameter %q", field)
		} else {
			assertSafeError(t, err)
		}
	}
	for _, field := range []string{"v", "_site", "_lang", "_m", "_os_ver", "_os_dev", "_os_dim", "_uid"} {
		config := testConfig("https://example.test/client.php", nil)
		delete(config.CommonParameters, field)
		if _, err := NewClient(config); err == nil {
			t.Errorf("accepted missing common parameter %q", field)
		}
	}
	for _, uid := range []string{"", "device-id", "设备", "id\n"} {
		config := testConfig("https://example.test/client.php", nil)
		config.CommonParameters["_uid"] = uid
		if _, err := NewClient(config); err == nil {
			t.Errorf("accepted invalid uid %q", uid)
		}
	}
	config := testConfig("https://example.test/client.php", nil)
	config.SigningSeed = ""
	if _, err := NewClient(config); err == nil {
		t.Fatal("accepted an empty signing seed")
	}
	config = testConfig("https://example.test/client.php", nil)
	config.CommonParameters["bad&field"] = "value"
	if _, err := NewClient(config); err == nil {
		t.Fatal("accepted an invalid form field name")
	}
}

func TestClientCopiesCallerConfiguration(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("_site") != "ajs" {
			t.Error("caller mutation changed client common parameters")
		}
		io.WriteString(writer, validReply)
	}))
	defer server.Close()
	config := testConfig(server.URL, server.Client())
	initial := make(map[string]string, len(config.CommonParameters))
	for key, value := range config.CommonParameters {
		initial[key] = value
	}
	transport := config.HTTPClient.Transport
	client := newTestClient(t, config)
	if !reflect.DeepEqual(config.CommonParameters, initial) || config.HTTPClient.Timeout != 0 || config.HTTPClient.CheckRedirect != nil || config.HTTPClient.Transport != transport {
		t.Fatal("NewClient modified caller configuration")
	}
	if client.httpClient.Timeout != defaultHTTPTimeout {
		t.Fatal("default timeout was not applied to the copied client")
	}
	config.CommonParameters["_site"] = "caller changed value"
	config.HTTPClient.Timeout = time.Nanosecond
	_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := config.CommonParameters["password"]; exists {
		t.Fatal("Login inserted credentials into caller parameters")
	}
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (transport testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestLoginSanitizesTransportAndClockErrors(t *testing.T) {
	sensitive := testPassword + testSeed + testToken
	var calls atomic.Int32
	originalCause := &testDiagnosticError{detail: "transport failure containing " + sensitive}
	config := testConfig("https://example.test/client.php", &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, originalCause
	})})
	client := newTestClient(t, config)
	_, err := client.Login(context.Background(), testUsername, []byte(testPassword))
	if err == nil || calls.Load() != 1 {
		t.Fatal("transport error was ignored or login retried")
	}
	assertSafeError(t, err)
	assertDiagnosticCause(t, err, originalCause)
	config.NowMilliseconds = func() (uint64, error) { return 0, originalCause }
	client = newTestClient(t, config)
	_, err = client.Login(context.Background(), testUsername, []byte(testPassword))
	if err == nil || calls.Load() != 1 {
		t.Fatal("clock failure was ignored or sent a request")
	}
	assertSafeError(t, err)
	assertDiagnosticCause(t, err, originalCause)
}

func TestLoginRequiresCredentials(t *testing.T) {
	var calls atomic.Int32
	httpClient := &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected request")
	})}
	client := newTestClient(t, testConfig("https://example.test/client.php", httpClient))
	for _, input := range []struct {
		username string
		password []byte
	}{
		{username: testUsername},
		{password: []byte(testPassword)},
		{username: " \t ", password: []byte(testPassword)},
		{username: "account\rname", password: []byte(testPassword)},
		{username: "account\nname", password: []byte(testPassword)},
		{username: "account\x00name", password: []byte(testPassword)},
		{username: testUsername, password: bytes.Repeat([]byte{'x'}, maxPasswordBytes+1)},
	} {
		if _, err := client.Login(context.Background(), input.username, input.password); err == nil {
			t.Fatal("accepted missing login credentials")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid credentials sent a request")
	}
}

type testDiagnosticError struct{ detail string }

func (err *testDiagnosticError) Error() string { return err.detail }

func assertDiagnosticCause(t *testing.T, err error, cause *testDiagnosticError) {
	t.Helper()
	var diagnostic *testDiagnosticError
	if !errors.Is(err, cause) || !errors.As(err, &diagnostic) || diagnostic != cause {
		t.Fatal("safe error discarded the diagnostic cause")
	}
}

func TestMonotonicMilliseconds(t *testing.T) {
	first, err := MonotonicMilliseconds()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		if err == nil {
			t.Fatal("unsupported platform returned a monotonic login clock")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := MonotonicMilliseconds()
	if err != nil || second < first {
		t.Fatalf("monotonic milliseconds moved backwards: %d -> %d, %v", first, second, err)
	}
}

func assertSafeError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, secret := range []string{testPassword, testSeed, testToken} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("error contains sensitive authentication data")
		}
	}
}
