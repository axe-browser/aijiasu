package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
)

type fakeLoginClient func(context.Context, string, []byte) (clientapi.Session, error)

func (client fakeLoginClient) Login(ctx context.Context, username string, password []byte) (clientapi.Session, error) {
	return client(ctx, username, password)
}

func testDependencies() cliDependencies {
	return cliDependencies{
		defaultDirectory: func() (string, error) { return filepath.Join("private", "test-config"), nil },
		loadProfile: func(string) (clientapi.Profile, error) {
			return clientapi.Profile{
				Version:          1,
				Endpoint:         "https://example.test/client",
				ClientVersion:    "test-version",
				SigningSeed:      "synthetic-profile-seed",
				CommonParameters: map[string]string{"test-field": "test-value"},
			}, nil
		},
		newClient: func(clientapi.Config) (loginClient, error) {
			return fakeLoginClient(func(_ context.Context, username string, _ []byte) (clientapi.Session, error) {
				return clientapi.Session{Username: username, LoginToken: "synthetic-login-token"}, nil
			}), nil
		},
		beginLogin:       func(context.Context, string) (authstore.LoginVersion, error) { return authstore.LoginVersion{}, nil },
		saveLoginSession: func(context.Context, string, authstore.LoginVersion, clientapi.Session) error { return nil },
		readPassword: func(context.Context) ([]byte, error) {
			return []byte("synthetic-interactive-password"), nil
		},
	}
}

func TestLoginUsernameAliasesAndPrivateSession(t *testing.T) {
	for _, usernameFlag := range []string{"-u", "--username"} {
		t.Run(usernameFlag, func(t *testing.T) {
			dependencies := testDependencies()
			var saved bool
			dependencies.newClient = func(config clientapi.Config) (loginClient, error) {
				if config.Endpoint != "https://example.test/client" || config.SigningSeed != "synthetic-profile-seed" || config.CommonParameters["test-field"] != "test-value" || config.NowMilliseconds == nil {
					t.Fatal("client did not receive validated profile and monotonic clock")
				}
				return fakeLoginClient(func(_ context.Context, username string, password []byte) (clientapi.Session, error) {
					if username != "test-account" || string(password) != "  密码 +&=  " {
						t.Fatal("login changed the supplied credentials")
					}
					return clientapi.Session{Username: username, LoginToken: "synthetic-login-token"}, nil
				}), nil
			}
			dependencies.saveLoginSession = func(_ context.Context, directory string, _ authstore.LoginVersion, session clientapi.Session) error {
				if directory != filepath.Join("private", "test-config") || session.Username != "test-account" || session.LoginToken != "synthetic-login-token" {
					t.Fatal("session did not reach private storage intact")
				}
				saved = true
				return nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"login", usernameFlag, "test-account", "--password-stdin"}, strings.NewReader("  密码 +&=  \r\nignored second line\n"), &stdout, &stderr, dependencies)
			if code != 0 || !saved || !strings.Contains(stdout.String(), "登录成功") {
				t.Fatalf("successful login = code %d, saved %t, output %q", code, saved, stdout.String())
			}
			for _, secret := range []string{"密码 +&=", "synthetic-login-token", "synthetic-profile-seed"} {
				if strings.Contains(stdout.String()+stderr.String(), secret) {
					t.Fatal("login output disclosed a secret")
				}
			}
		})
	}
}

func TestLoginProfileAndClientValidationPrecedePassword(t *testing.T) {
	for _, stage := range []string{"profile", "client"} {
		t.Run(stage, func(t *testing.T) {
			dependencies := testDependencies()
			passwordReads := 0
			dependencies.readPassword = func(context.Context) ([]byte, error) {
				passwordReads++
				return []byte("secret-input"), nil
			}
			if stage == "profile" {
				dependencies.loadProfile = func(string) (clientapi.Profile, error) {
					return clientapi.Profile{}, errors.New("synthetic-profile-seed")
				}
			} else {
				dependencies.newClient = func(clientapi.Config) (loginClient, error) {
					return nil, errors.New("synthetic-profile-seed")
				}
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"login", "-u", "test-account"}, nil, &stdout, &stderr, dependencies)
			if code == 0 || passwordReads != 0 || stdout.Len() != 0 || strings.Contains(stderr.String(), "synthetic-profile-seed") {
				t.Fatalf("invalid %s solicited credentials or disclosed profile contents", stage)
			}
		})
	}
}

func TestLoginExplicitConfigurationPaths(t *testing.T) {
	dependencies := testDependencies()
	dependencies.defaultDirectory = func() (string, error) {
		t.Fatal("explicit config directory must not resolve the user's real directory")
		return "", nil
	}
	dependencies.loadProfile = func(path string) (clientapi.Profile, error) {
		if path != filepath.Join("selected", "profile.json") {
			t.Fatalf("profile path = %q", path)
		}
		return clientapi.Profile{}, nil
	}
	dependencies.saveLoginSession = func(_ context.Context, directory string, _ authstore.LoginVersion, _ clientapi.Session) error {
		if directory != filepath.Join("selected", "state") {
			t.Fatalf("session directory = %q", directory)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"login", "-u", "test-account", "--profile", filepath.Join("selected", "profile.json"), "--config-dir", filepath.Join("selected", "state"), "--password-stdin"}, strings.NewReader("synthetic-password\n"), &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("explicit configuration failed: %s", stderr.String())
	}
}

func TestLoginRejectsInvalidArgumentsWithoutEchoingThem(t *testing.T) {
	for _, args := range [][]string{
		{"login", "-u", "test-account", "--unknown-password-option=DO_NOT_PRINT"},
		{"login", "-u", "test-account", "DO_NOT_PRINT"},
		{"login", "DO_NOT_PRINT"},
		{"DO_NOT_PRINT"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, nil, &stdout, &stderr, cliDependencies{})
		if code != exitUsage || strings.Contains(stdout.String()+stderr.String(), "DO_NOT_PRINT") {
			t.Fatalf("unsafe argument handling: code %d", code)
		}
	}
}

func TestLoginFailuresNeverDiscloseSecretsOrClaimSuccess(t *testing.T) {
	for _, stage := range []string{"directory", "profile", "client", "password", "login", "missing-token", "save"} {
		t.Run(stage, func(t *testing.T) {
			dependencies := testDependencies()
			secret := "DO_NOT_PRINT_PASSWORD_TOKEN_SEED_OR_RAW_RESPONSE"
			failure := errors.New(secret)
			saveCalls := 0
			dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
				saveCalls++
				if stage == "save" {
					return failure
				}
				return nil
			}
			switch stage {
			case "directory":
				dependencies.defaultDirectory = func() (string, error) { return "", failure }
			case "profile":
				dependencies.loadProfile = func(string) (clientapi.Profile, error) { return clientapi.Profile{}, failure }
			case "client":
				dependencies.newClient = func(clientapi.Config) (loginClient, error) { return nil, failure }
			case "password":
				dependencies.readPassword = func(context.Context) ([]byte, error) { return nil, failure }
			case "login", "missing-token":
				dependencies.newClient = func(clientapi.Config) (loginClient, error) {
					return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
						if stage == "login" {
							return clientapi.Session{}, failure
						}
						return clientapi.Session{}, nil
					}), nil
				}
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"login", "-u", "test-account"}, nil, &stdout, &stderr, dependencies)
			if code == 0 || stdout.Len() != 0 || strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), "登录成功") {
				t.Fatalf("unsafe %s failure: code %d", stage, code)
			}
			if stage != "save" && saveCalls != 0 {
				t.Fatalf("%s failure changed session storage", stage)
			}
		})
	}
}

func TestLoginErrorCategoriesUseSafeFixedMessages(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		message string
	}{
		{name: "authentication", err: clientapi.ErrAuthRejected, message: "登录被拒绝，请检查账号、密码及账户状态。"},
		{name: "invalid response", err: clientapi.ErrInvalidResponse, message: "服务响应格式不兼容，无法确认登录状态。"},
		{name: "oversized response", err: clientapi.ErrResponseTooLarge, message: "服务响应格式不兼容，无法确认登录状态。"},
		{name: "TLS verification", err: clientapi.ErrTLSVerification, message: "登录服务证书验证失败，已停止登录；请检查当前网络或联系服务方。"},
		{name: "timeout", err: context.DeadlineExceeded, message: "登录请求超时，请检查网络后重试。"},
		{name: "other", err: errors.New("unclassified failure"), message: "登录失败，请检查账号、密码、兼容配置及网络后重试。"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const secret = "DO_NOT_PRINT_PASSWORD_TOKEN_SEED_OR_RAW_RESPONSE"
			dependencies := testDependencies()
			dependencies.newClient = func(clientapi.Config) (loginClient, error) {
				return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
					return clientapi.Session{}, errors.Join(test.err, errors.New(secret))
				}), nil
			}
			saveCalls := 0
			dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
				saveCalls++
				return nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"login", "-u", "test-account", "--password-stdin"}, strings.NewReader("synthetic-password\n"), &stdout, &stderr, dependencies)
			if code != exitFailure || saveCalls != 0 || stdout.Len() != 0 || stderr.String() != test.message+"\n" {
				t.Fatalf("unexpected safe diagnostic for %s: code %d, saved %d, stderr %q", test.name, code, saveCalls, stderr.String())
			}
			if strings.Contains(stderr.String(), secret) {
				t.Fatal("categorized login error disclosed a secret")
			}
		})
	}
}

func TestReadPasswordLineBoundariesAndErrors(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "spaces", input: "  password  \n", want: "  password  "},
		{name: "CRLF", input: "password\r\n", want: "password"},
		{name: "EOF", input: "password", want: "password"},
		{name: "one line", input: "first\nsecond\n", want: "first"},
		{name: "empty", input: "\n", wantErr: errPasswordEmpty},
		{name: "empty EOF", input: "", wantErr: errPasswordEmpty},
		{name: "max CRLF", input: strings.Repeat("x", maxPasswordBytes) + "\r\n", want: strings.Repeat("x", maxPasswordBytes)},
		{name: "too long", input: strings.Repeat("x", maxPasswordBytes+1) + "\n", wantErr: errPasswordTooLong},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readPasswordLine(strings.NewReader(test.input))
			if !errors.Is(err, test.wantErr) || string(got) != test.want {
				t.Fatalf("password line result has unexpected value or error")
			}
		})
	}
	want := errors.New("input failed")
	if _, err := readPasswordLine(io.MultiReader(strings.NewReader("partial-secret"), iotest.ErrReader(want))); !errors.Is(err, want) {
		t.Fatalf("password reader did not preserve input error: %v", err)
	}
}

type oneLineReader struct {
	reads int
}

func (reader *oneLineReader) Read(buffer []byte) (int, error) {
	reader.reads++
	if reader.reads != 1 {
		return 0, errors.New("reading past the password line would block")
	}
	return copy(buffer, "password\n"), nil
}

func TestPasswordStdinDoesNotWaitForEOF(t *testing.T) {
	reader := &oneLineReader{}
	password, err := readPasswordLine(reader)
	if err != nil || string(password) != "password" || reader.reads != 1 {
		t.Fatal("password input waited for EOF after a complete line")
	}
}

func TestPasswordStdinCancellationWithOpenPipeDoesNotLogin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	dependencies := testDependencies()
	loginCalls, saveCalls := 0, 0
	dependencies.newClient = func(clientapi.Config) (loginClient, error) {
		return fakeLoginClient(func(context.Context, string, []byte) (clientapi.Session, error) {
			loginCalls++
			return clientapi.Session{LoginToken: "synthetic-token"}, nil
		}), nil
	}
	dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
		saveCalls++
		return nil
	}
	var stdout, stderr bytes.Buffer
	finished := make(chan int, 1)
	go func() {
		finished <- run(ctx, []string{"login", "-u", "test-account", "--password-stdin"}, reader, &stdout, &stderr, dependencies)
	}()
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, "partial-secret-without-newline")
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("provide partial password: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("login never started reading password stdin")
	}
	// The writer remains open and no complete line or EOF has been supplied.
	cancel()
	select {
	case code := <-finished:
		if code != exitCancelled || loginCalls != 0 || saveCalls != 0 || stdout.Len() != 0 || stderr.String() != "操作已取消。\n" {
			t.Fatalf("cancelled open pipe: exit %d, login calls %d, save calls %d", code, loginCalls, saveCalls)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("password stdin cancellation waited for newline or EOF")
	}
}

func TestHelpAndVersionDoNotRequireCredentials(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"help", "login"}, {"login", "--help"}, {"version"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, nil, &stdout, &stderr, cliDependencies{}); code != 0 || stdout.Len() == 0 {
			t.Fatalf("help/version failed: args %v, code %d", args, code)
		}
	}
}

func TestCancelledLoginDoesNotReadCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"login", "-u", "test-account"}, nil, &stdout, &stderr, cliDependencies{})
	if code != exitCancelled || stdout.Len() != 0 {
		t.Fatalf("cancelled login exit = %d", code)
	}
}
