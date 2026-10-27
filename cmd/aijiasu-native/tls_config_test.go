package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
)

func TestLoginTLSFingerprintConfigurationAndOverride(t *testing.T) {
	for _, override := range []bool{false, true} {
		dependencies := testDependencies()
		load := dependencies.loadProfile
		dependencies.loadProfile = func(path string) (clientapi.Profile, error) {
			profile, err := load(path)
			profile.TLSSPKISHA256 = strings.Repeat("a", 64)
			return profile, err
		}
		dependencies.newClient = func(config clientapi.Config) (loginClient, error) {
			expected := strings.Repeat("a", 64)
			if override {
				expected = strings.Repeat("b", 64)
			}
			if config.TLSSPKISHA256 != expected {
				t.Fatal("TLS public key fingerprint did not reach login client")
			}
			return testDependencies().newClient(config)
		}
		args := []string{"login", "-u", "public-account", "--password-stdin"}
		if override {
			args = append(args, "--tls-pin", strings.Repeat("b", 64))
		}
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, strings.NewReader("public-test-password\n"), &stdout, &stderr, dependencies); code != 0 {
			t.Fatalf("login TLS config code %d", code)
		}
	}
}

func TestRefreshTLSFingerprintConfigurationAndOverride(t *testing.T) {
	for _, override := range []bool{false, true} {
		dependencies := clientCommandDependencies(t)
		dependencies.loadProfile = func(string) (clientapi.Profile, error) {
			return clientapi.Profile{TLSSPKISHA256: strings.Repeat("a", 64)}, nil
		}
		dependencies.newSyncClient = func(config clientapi.Config) (syncClient, error) {
			expected := strings.Repeat("a", 64)
			if override {
				expected = strings.Repeat("b", 64)
			}
			if config.TLSSPKISHA256 != expected {
				t.Fatal("TLS fingerprint did not reach token refresh client")
			}
			return fakeSyncClient(func(_ context.Context, session clientapi.Session) (clientapi.Session, error) { return session, nil }), nil
		}
		dependencies.sessionVersion = func(context.Context, string, clientapi.Session) (authstore.SessionVersion, error) {
			return authstore.SessionVersion{}, nil
		}
		dependencies.saveRefreshedSession = func(context.Context, string, authstore.SessionVersion, clientapi.Session) error { return nil }
		args := []string{"refresh", "--json"}
		if override {
			args = append(args, "--tls-pin", strings.Repeat("b", 64))
		}
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies); code != 0 {
			t.Fatalf("refresh TLS config code %d", code)
		}
	}
}
