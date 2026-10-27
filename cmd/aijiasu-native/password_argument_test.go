package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
)

func TestLoginPasswordArgumentAliasesPreserveBytesAndClearBuffer(t *testing.T) {
	const password = "  公开测试密码 +&=$!\\\"/?=  "
	for _, flag := range []string{"-p", "--password"} {
		for _, equals := range []bool{false, true} {
			name := flag
			if equals {
				name += "=value"
			}
			t.Run(name, func(t *testing.T) {
				dependencies := testDependencies()
				dependencies.readPassword = func(context.Context) ([]byte, error) {
					t.Fatal("explicit password argument read from terminal")
					return nil, nil
				}
				var passedPassword []byte
				loginCalls, saveCalls := 0, 0
				dependencies.newClient = func(clientapi.Config) (loginClient, error) {
					return fakeLoginClient(func(_ context.Context, username string, supplied []byte) (clientapi.Session, error) {
						loginCalls++
						if username != "public-fixture-account" || string(supplied) != password {
							t.Fatal("password argument bytes or account changed")
						}
						passedPassword = supplied
						return clientapi.Session{Username: username, LoginToken: clientFixtureSecret}, nil
					}), nil
				}
				dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
					saveCalls++
					return nil
				}
				args := []string{"login", "-u", "public-fixture-account"}
				if equals {
					args = append(args, flag+"="+password)
				} else {
					args = append(args, flag, password)
				}
				var stdout, stderr bytes.Buffer
				code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
				if code != 0 || loginCalls != 1 || saveCalls != 1 || !strings.Contains(stdout.String(), "登录成功") {
					t.Fatalf("password argument login = code %d login %d save %d, output %q / %q", code, loginCalls, saveCalls, stdout.String(), stderr.String())
				}
				if len(passedPassword) != len(password) || !bytes.Equal(passedPassword, make([]byte, len(password))) {
					t.Fatal("password buffer retained argument contents after login returned")
				}
				assertClientOutputSafe(t, &stdout, &stderr, password)
			})
		}
	}
}

func TestLoginPasswordArgumentFailuresAreSafeAndClearBuffer(t *testing.T) {
	const password = "PUBLIC_TEST_PASSWORD_NEVER_PRINT"
	const serviceError = "PUBLIC_TEST_RAW_SERVICE_ERROR_NEVER_PRINT"
	for _, stage := range []string{"login", "auth-rejected", "save"} {
		t.Run(stage, func(t *testing.T) {
			dependencies := testDependencies()
			dependencies.readPassword = func(context.Context) ([]byte, error) {
				t.Fatal("password argument failure read terminal password")
				return nil, nil
			}
			var passedPassword []byte
			dependencies.newClient = func(clientapi.Config) (loginClient, error) {
				return fakeLoginClient(func(_ context.Context, username string, supplied []byte) (clientapi.Session, error) {
					passedPassword = supplied
					if string(supplied) != password {
						t.Fatal("incorrect explicit password reached client")
					}
					if stage == "auth-rejected" {
						return clientapi.Session{}, errors.Join(clientapi.ErrAuthRejected, errors.New(serviceError+password))
					}
					if stage == "login" {
						return clientapi.Session{}, errors.New(serviceError + password)
					}
					return clientapi.Session{Username: username, LoginToken: clientFixtureSecret}, nil
				}), nil
			}
			saveCalls := 0
			dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
				saveCalls++
				return errors.New(serviceError + password)
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"login", "-u", "public-fixture-account", "-p", password}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			wantSaves := 0
			if stage == "save" {
				wantSaves = 1
			}
			if code != exitFailure || saveCalls != wantSaves || stdout.Len() != 0 || len(passedPassword) != len(password) || !bytes.Equal(passedPassword, make([]byte, len(password))) {
				t.Fatalf("password argument %s failure = code %d saves %d", stage, code, saveCalls)
			}
			assertClientOutputSafe(t, &stdout, &stderr, password, serviceError)
		})
	}
}

func TestLoginPasswordArgumentConflictsAndDuplicatesAreRejectedBeforeProfile(t *testing.T) {
	const password = "PUBLIC_TEST_SECRET_CONFLICT_ARGUMENT"
	for _, flags := range [][]string{
		{"-p", password, "--password-stdin"},
		{"--password-stdin", "--password", password},
		{"-p", password, "-p", password},
		{"--password", password, "--password", password},
		{"-p", password, "--password", password},
		{"--password=" + password, "-p=" + password},
	} {
		dependencies := testDependencies()
		dependencies.loadProfile = func(string) (clientapi.Profile, error) {
			t.Fatal("conflicting password flags read profile before being rejected")
			return clientapi.Profile{}, nil
		}
		dependencies.newClient = func(clientapi.Config) (loginClient, error) {
			t.Fatal("conflicting password flags constructed login client")
			return nil, nil
		}
		dependencies.readPassword = func(context.Context) ([]byte, error) {
			t.Fatal("conflicting password flags read terminal")
			return nil, nil
		}
		dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
			t.Fatal("conflicting password flags saved a session")
			return nil
		}
		var stdout, stderr bytes.Buffer
		args := append([]string{"login", "-u", "public-fixture-account"}, flags...)
		code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
		if code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("conflicting flags = code %d output %q / %q", code, stdout.String(), stderr.String())
		}
		assertClientOutputSafe(t, &stdout, &stderr, password)
	}
}

func TestLoginPasswordArgumentEmptyAndOversizeDoNotAuthenticateOrSave(t *testing.T) {
	for _, password := range []string{"", strings.Repeat("PUBLIC_TEST_OVERSIZE_PASSWORD_", 200)} {
		dependencies := testDependencies()
		dependencies.newClient = func(clientapi.Config) (loginClient, error) {
			return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
				t.Fatal("empty or oversize argument reached authentication")
				return clientapi.Session{}, nil
			}), nil
		}
		dependencies.readPassword = func(context.Context) ([]byte, error) {
			t.Fatal("empty or oversize explicit password fell back to terminal")
			return nil, nil
		}
		dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
			t.Fatal("empty or oversize argument changed saved session")
			return nil
		}
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"login", "-u", "public-fixture-account", "--password=" + password}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
		if code == 0 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("invalid password size = code %d output %q / %q", code, stdout.String(), stderr.String())
		}
		assertClientOutputSafe(t, &stdout, &stderr, password, "PUBLIC_TEST_OVERSIZE_PASSWORD_")
	}
}

func TestLoginHelpDoesNotRevealSuppliedPasswordArgument(t *testing.T) {
	const password = "PUBLIC_TEST_HELP_PASSWORD_NEVER_PRINT"
	for _, args := range [][]string{
		{"login", "-u", "public-fixture-account", "-p", password, "--help"},
		{"login", "--password=" + password, "--help"},
		{"login", "--help", "--password", password},
	} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, cliDependencies{})
		if code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("password argument help = code %d output %q / %q", code, stdout.String(), stderr.String())
		}
		assertClientOutputSafe(t, &stdout, &stderr, password)
	}
}
