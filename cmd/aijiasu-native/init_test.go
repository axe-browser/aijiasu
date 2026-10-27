package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"aijiasu-native/internal/native/bootstrap"
)

func TestInitPassesOptionsAndReturnsOnlyPublicResult(t *testing.T) {
	dependencies := testDependencies()
	dependencies.initialize = func(_ context.Context, options bootstrap.Options) (bootstrap.Result, error) {
		if options.Directory != "/synthetic/private" || options.Reference != "/synthetic/reference" || options.TLSPin != strings.Repeat("a", 64) {
			t.Fatal("init options changed")
		}
		return bootstrap.Result{Initialized: true, Created: []string{"compatibility.json", "transport.json"}, Preserved: []string{}}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"init", "--config-dir", "/synthetic/private", "--reference", "/synthetic/reference", "--tls-pin", strings.Repeat("a", 64), "--json"}, nil, &stdout, &stderr, dependencies)
	var result bootstrap.Result
	if code != 0 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &result) != nil || !result.Initialized || len(result.Created) != 2 {
		t.Fatalf("init code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "synthetic") || strings.Contains(stdout.String(), strings.Repeat("a", 64)) {
		t.Fatal("init response exposed private options")
	}
}

func TestInitDefaultsValidationCancellationAndSafeFailure(t *testing.T) {
	for _, mode := range []string{"default", "bad-pin", "positional", "failed", "canceled", "help"} {
		t.Run(mode, func(t *testing.T) {
			dependencies := testDependencies()
			calls := 0
			dependencies.initialize = func(_ context.Context, options bootstrap.Options) (bootstrap.Result, error) {
				calls++
				if options.Directory == "" {
					t.Fatal("missing default directory")
				}
				if mode == "failed" {
					return bootstrap.Result{}, errors.New("synthetic-sensitive-private-material")
				}
				return bootstrap.Result{Initialized: true, Created: []string{}, Preserved: []string{"compatibility.json", "transport.json"}}, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			args := []string{"init"}
			want := 0
			switch mode {
			case "bad-pin":
				args = append(args, "--tls-pin", "sensitive-invalid-input")
				want = exitUsage
			case "positional":
				args = append(args, "unexpected-private-value")
				want = exitUsage
			case "failed":
				want = exitFailure
			case "canceled":
				cancel()
				want = exitCancelled
			case "help":
				args = append(args, "--help")
			}
			var stdout, stderr bytes.Buffer
			if code := run(ctx, args, nil, &stdout, &stderr, dependencies); code != want {
				t.Fatalf("code=%d expected=%d", code, want)
			}
			if (mode == "default" || mode == "failed") && calls != 1 {
				t.Fatal("init implementation was not called")
			}
			if (mode == "bad-pin" || mode == "positional" || mode == "canceled" || mode == "help") && calls != 0 {
				t.Fatal("invalid or canceled init changed configuration")
			}
			if strings.Contains(stdout.String()+stderr.String(), "sensitive") || strings.Contains(stdout.String()+stderr.String(), "unexpected-private-value") {
				t.Fatal("failure exposed private input")
			}
		})
	}
}
