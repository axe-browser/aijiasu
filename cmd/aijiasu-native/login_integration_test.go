package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"aijiasu-native/internal/native/clientapi"
)

func TestLoginWithPrivateProfileHTTPAndSessionStore(t *testing.T) {
	const seed = "constructed-integration-profile"
	const password = "constructed password +&="
	const token = "constructed-integration-session"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error("cannot read constructed request")
		}
		if request.Header.Get("X-Timestamp") != "123456789" ||
			request.Header.Get("X-Sig") != clientapi.RequestSignature(seed, string(body), 123456789) {
			t.Error("private profile and client did not produce the expected signature")
		}
		if !bytes.Contains(body, []byte("password=constructed%20password%20%2b%26%3d")) {
			t.Error("password was not transferred using the observed form encoding")
		}
		io.WriteString(writer, `{"Login":{"AuthResult":"OK","LoginToken":"constructed-integration-session","ExpireTime":1800000000}}`)
	}))
	defer server.Close()

	directory := privateCLIStateDirectory(t)
	profile := clientapi.Profile{
		Version: 1, Endpoint: server.URL + "/client.php", ClientVersion: "4.3.0.1", SigningSeed: seed,
		CommonParameters: map[string]string{
			"v": "4.3.0.1", "_site": "ajs", "_lang": "en", "_m": "linux",
			"_os_ver": "constructed OS", "_os_dev": "arm64", "_os_dim": "lid=constructed", "_uid": "constructedUID123",
		},
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "compatibility.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies := defaultDependencies()
	dependencies.defaultDirectory = func() (string, error) { return directory, nil }
	dependencies.newClient = func(config clientapi.Config) (loginClient, error) {
		config.HTTPClient = server.Client()
		config.NowMilliseconds = func() (uint64, error) { return 123456789, nil }
		return clientapi.NewClient(config)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"login", "-u", "constructed-account", "--password-stdin"},
		strings.NewReader(password+"\n"), &stdout, &stderr, dependencies)
	if code != 0 || !strings.Contains(stdout.String(), "登录成功") {
		t.Fatalf("integrated login failed with code %d: %s", code, stderr.String())
	}
	for _, secret := range []string{seed, password, token} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("integrated command output disclosed authentication input")
		}
	}
	path := filepath.Join(directory, "session.json")
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var session clientapi.Session
	if err := json.Unmarshal(stored, &session); err != nil {
		t.Fatal(err)
	}
	if session.Username != "constructed-account" || session.LoginToken != token || session.AuthenticatedAt.IsZero() {
		t.Fatal("authenticated session did not reach private storage")
	}
	if bytes.Contains(stored, []byte(seed)) || bytes.Contains(stored, []byte(password)) {
		t.Fatal("stored session contains credentials outside the session allowlist")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatal("integrated login did not save a private session")
	}
}
