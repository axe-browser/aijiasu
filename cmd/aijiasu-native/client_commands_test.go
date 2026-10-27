package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	clientruntime "aijiasu-native/internal/native/runtime"
)

const clientFixtureSecret = "PUBLIC_TEST_FIXTURE_DO_NOT_PRINT_PASSWORD_TOKEN_OR_SEED"

type fakeSyncClient func(context.Context, clientapi.Session) (clientapi.Session, error)

func (client fakeSyncClient) Refresh(ctx context.Context, session clientapi.Session) (clientapi.Session, error) {
	return client(ctx, session)
}

type forbiddenClientInput struct{ testing *testing.T }

func (reader forbiddenClientInput) Read([]byte) (int, error) {
	reader.testing.Helper()
	reader.testing.Fatal("command read password stdin unexpectedly")
	return 0, io.EOF
}

func clientFixtureSession() clientapi.Session {
	return clientapi.Session{
		Username: "public-test-account", ServiceUsername: "public-test-service-account",
		LoginToken: clientFixtureSecret,
		Nodes: []clientapi.Node{
			{ID: "210", Title: "浙江省 杭州市 一号", Status: "可用", Host: "hangzhou.example.test", TCPPort: 443},
			{ID: "211", Title: "浙江省 宁波市 包含210的名称", Status: "可用", Host: "ningbo.example.test", TCPPort: 4443},
			{ID: "310", Title: "江苏省 南京市 一号", Status: "可用", Host: "nanjing.example.test", TCPPort: 443},
		},
	}
}

func clientCommandDependencies(t *testing.T) cliDependencies {
	t.Helper()
	dependencies := testDependencies()
	dependencies.loadSession = func(directory string) (clientapi.Session, error) {
		if directory != filepath.Join("private", "test-config") {
			t.Fatalf("unexpected session directory: %q", directory)
		}
		return clientFixtureSession(), nil
	}
	dependencies.loadProfile = func(string) (clientapi.Profile, error) {
		t.Fatal("command read compatibility profile unexpectedly")
		return clientapi.Profile{}, nil
	}
	dependencies.newClient = func(clientapi.Config) (loginClient, error) {
		t.Fatal("command constructed password-login client unexpectedly")
		return nil, nil
	}
	dependencies.newSyncClient = func(clientapi.Config) (syncClient, error) {
		t.Fatal("command constructed network synchronization client unexpectedly")
		return nil, nil
	}
	dependencies.readPassword = func(context.Context) ([]byte, error) {
		t.Fatal("command requested a password unexpectedly")
		return nil, nil
	}
	dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
		t.Fatal("command changed session storage unexpectedly")
		return nil
	}
	dependencies.sessionVersion = func(context.Context, string, clientapi.Session) (authstore.SessionVersion, error) {
		t.Fatal("command captured session version unexpectedly")
		return authstore.SessionVersion{}, nil
	}
	dependencies.saveRefreshedSession = func(context.Context, string, authstore.SessionVersion, clientapi.Session) error {
		t.Fatal("command changed refreshed session storage unexpectedly")
		return nil
	}
	dependencies.logoutSession = func(context.Context, string, func() error) error {
		t.Fatal("command removed session storage unexpectedly")
		return nil
	}
	dependencies.loadTransport = func(string) (authstore.TransportProfile, error) {
		t.Fatal("command read transport profile unexpectedly")
		return authstore.TransportProfile{}, nil
	}
	dependencies.runtimeCall = func(context.Context, string, clientruntime.Request) (clientruntime.Status, error) {
		t.Fatal("command contacted proxy runtime unexpectedly")
		return clientruntime.Status{}, nil
	}
	dependencies.runtimeRun = func(context.Context, clientruntime.Config, string, func(clientruntime.Status)) error {
		t.Fatal("command started a proxy runtime unexpectedly")
		return nil
	}
	return dependencies
}

func assertClientOutputSafe(t *testing.T, stdout, stderr *bytes.Buffer, additional ...string) {
	t.Helper()
	for _, secret := range append([]string{clientFixtureSecret, "synthetic-profile-seed", "synthetic-login-token"}, additional...) {
		if secret != "" && strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("client command disclosed a sensitive fixture")
		}
	}
}

func TestNodesUsesCachedSessionWithoutPasswordProfileOrNetwork(t *testing.T) {
	for _, command := range []string{"nodes", "list"} {
		t.Run(command, func(t *testing.T) {
			dependencies := clientCommandDependencies(t)
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{command, "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			var nodes []clientapi.Node
			if code != 0 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &nodes) != nil || !reflect.DeepEqual(nodes, clientFixtureSession().Nodes) {
				t.Fatalf("cached %s = code %d, stdout %q, stderr %q", command, code, stdout.String(), stderr.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
	t.Run("cached-empty-list", func(t *testing.T) {
		dependencies := clientCommandDependencies(t)
		dependencies.loadSession = func(string) (clientapi.Session, error) {
			session := clientFixtureSession()
			session.Nodes = []clientapi.Node{}
			return session, nil
		}
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"nodes", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
		if code != 0 || stdout.String() != "[]\n" || stderr.Len() != 0 {
			t.Fatalf("empty cached list = code %d, %q / %q", code, stdout.String(), stderr.String())
		}
	})
}

func TestNodesFilterPrefersExactIDAndMatchesChineseTitles(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		ids  []string
	}{
		{"exact-id-before-title", []string{"-n", "210"}, []string{"210"}},
		{"positional-id", []string{"210"}, []string{"210"}},
		{"province", []string{"-p", "浙江"}, []string{"210", "211"}},
		{"province-and-city", []string{"-p", "浙江", "-c", "杭州"}, []string{"210"}},
		{"title-substring", []string{"--node", "南京"}, []string{"310"}},
		{"no-title-match", []string{"-p", "浙江", "-c", "南京"}, []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := clientCommandDependencies(t)
			args := append([]string{"nodes", "--json"}, test.args...)
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			var nodes []clientapi.Node
			if code != 0 || json.Unmarshal(stdout.Bytes(), &nodes) != nil || nodes == nil {
				t.Fatalf("filtered nodes = code %d, %q", code, stdout.String())
			}
			ids := make([]string, 0, len(nodes))
			for _, node := range nodes {
				ids = append(ids, node.ID)
			}
			if !reflect.DeepEqual(ids, test.ids) {
				t.Fatalf("filtered ids = %v, want %v", ids, test.ids)
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestRefreshSaveFailureDoesNotPrintSuccessOrUpdatedNodes(t *testing.T) {
	dependencies := clientCommandDependencies(t)
	var calls []string
	dependencies.loadProfile = func(path string) (clientapi.Profile, error) {
		calls = append(calls, "profile")
		if path != filepath.Join("private", "test-config", "compatibility.json") {
			t.Fatalf("profile path = %q", path)
		}
		return clientapi.Profile{Endpoint: "https://example.test/", SigningSeed: clientFixtureSecret}, nil
	}
	updated := clientFixtureSession()
	updated.Nodes = []clientapi.Node{{ID: "fresh-node", Title: "不可在失败时显示的节点"}}
	dependencies.newSyncClient = func(config clientapi.Config) (syncClient, error) {
		calls = append(calls, "client")
		if config.SigningSeed != clientFixtureSecret || config.NowMilliseconds == nil {
			t.Fatal("refresh did not receive the supplied profile and clock")
		}
		return fakeSyncClient(func(_ context.Context, session clientapi.Session) (clientapi.Session, error) {
			calls = append(calls, "refresh")
			if session.LoginToken != clientFixtureSecret {
				t.Fatal("refresh did not receive cached token")
			}
			return updated, nil
		}), nil
	}
	dependencies.sessionVersion = func(context.Context, string, clientapi.Session) (authstore.SessionVersion, error) {
		calls = append(calls, "version")
		return authstore.SessionVersion{}, nil
	}
	dependencies.saveRefreshedSession = func(_ context.Context, directory string, _ authstore.SessionVersion, session clientapi.Session) error {
		calls = append(calls, "save")
		if directory != filepath.Join("private", "test-config") || !reflect.DeepEqual(session, updated) {
			t.Fatal("refreshed session did not reach private storage intact")
		}
		return errors.New(clientFixtureSecret)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"nodes", "--refresh", "--json"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != exitFailure || stdout.Len() != 0 || !reflect.DeepEqual(calls, []string{"profile", "client", "version", "refresh", "save"}) || !strings.Contains(stderr.String(), "刷新节点失败") {
		t.Fatalf("failed refresh = code %d, calls %v, output %q / %q", code, calls, stdout.String(), stderr.String())
	}
	assertClientOutputSafe(t, &stdout, &stderr, "fresh-node", "不可在失败时显示的节点")
}

func TestSwitchAvoidsCurrentNodeWithoutReadingCredentials(t *testing.T) {
	dependencies := clientCommandDependencies(t)
	dependencies.loadSession = func(string) (clientapi.Session, error) {
		session := clientFixtureSession()
		session.Nodes = session.Nodes[:2]
		return session, nil
	}
	var commands []string
	dependencies.runtimeCall = func(_ context.Context, directory string, request clientruntime.Request) (clientruntime.Status, error) {
		commands = append(commands, request.Command)
		if directory != filepath.Join("private", "test-config") {
			t.Fatal("runtime used an unexpected directory")
		}
		if request.Command == "status" {
			return clientruntime.Status{Running: true, Connected: true, NodeID: "210"}, nil
		}
		if request.Command != "switch" || request.NodeID != "211" {
			t.Fatalf("switch request = %#v", request)
		}
		return clientruntime.Status{Running: true, Connected: true, NodeID: "211", NodeTitle: "浙江省 宁波市", ListenAddress: "127.0.0.1:1080"}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"switch"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != 0 || !reflect.DeepEqual(commands, []string{"status", "switch"}) || !strings.Contains(stdout.String(), "已连接") || !strings.Contains(stdout.String(), "211") {
		t.Fatalf("switch = code %d, commands %v, output %q", code, commands, stdout.String())
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}

func TestActiveProxyRPCFailureNeverClaimsConnectionSuccess(t *testing.T) {
	for _, stage := range []string{"status", "connect"} {
		t.Run(stage, func(t *testing.T) {
			dependencies := clientCommandDependencies(t)
			var commands []string
			dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
				commands = append(commands, request.Command)
				if request.Command == stage {
					return clientruntime.Status{}, errors.New(clientFixtureSecret)
				}
				return clientruntime.Status{Running: true, Connected: true, NodeID: "210"}, nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"connect", "-n", "210"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			if code != exitFailure || stdout.Len() != 0 || strings.Contains(stderr.String(), "已连接") {
				t.Fatalf("RPC failure = code %d, commands %v, output %q / %q", code, commands, stdout.String(), stderr.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestConnectStatusCancellationReturnsCancelledWithoutPassword(t *testing.T) {
	dependencies := clientCommandDependencies(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
		if request.Command != "status" {
			t.Fatalf("unexpected runtime operation: %q", request.Command)
		}
		cancel()
		return clientruntime.Status{}, context.Canceled
	}
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"connect", "-n", "210"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != exitCancelled || stdout.Len() != 0 || stderr.String() != "操作已取消。\n" {
		t.Fatalf("canceled initial status = code %d, %q / %q", code, stdout.String(), stderr.String())
	}
}

func firstConnectDependencies(t *testing.T) cliDependencies {
	t.Helper()
	dependencies := clientCommandDependencies(t)
	dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
		if request.Command != "status" {
			t.Fatalf("first connect unexpectedly used runtime RPC %q", request.Command)
		}
		return clientruntime.Status{}, clientruntime.ErrNotRunning
	}
	dependencies.loadProfile = testDependencies().loadProfile
	dependencies.loadTransport = func(path string) (authstore.TransportProfile, error) {
		if path != filepath.Join("private", "test-config", "transport.json") {
			t.Fatalf("transport path = %q", path)
		}
		return authstore.TransportProfile{Version: 1, CoreVersion: "public-fixture-core"}, nil
	}
	return dependencies
}

func TestFirstConnectUsesForegroundRuntimeAndClearsOriginalPassword(t *testing.T) {
	for _, runError := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[runError], func(t *testing.T) {
			dependencies := firstConnectDependencies(t)
			password := []byte(clientFixtureSecret)
			dependencies.readPassword = func(context.Context) ([]byte, error) { return password, nil }
			runs := 0
			dependencies.runtimeRun = func(_ context.Context, config clientruntime.Config, nodeID string, ready func(clientruntime.Status)) error {
				runs++
				if nodeID != "210" || config.Directory != filepath.Join("private", "test-config") || config.ListenAddress != "127.0.0.1:1180" ||
					config.Session.LoginToken != clientFixtureSecret || config.Session.ServiceUsername != "public-test-service-account" ||
					config.Profile.SigningSeed != "synthetic-profile-seed" || config.Transport.CoreVersion != "public-fixture-core" || string(config.Password) != clientFixtureSecret {
					t.Fatal("first connect did not pass validated configuration and password to runtime")
				}
				if runError {
					return errors.New(clientFixtureSecret)
				}
				ready(clientruntime.Status{Running: true, Connected: true, NodeID: nodeID, NodeTitle: "浙江省 杭州市"})
				return nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"connect", "-n", "210", "--listen", "127.0.0.1:1180"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			expectedCode := 0
			if runError {
				expectedCode = exitFailure
			}
			if code != expectedCode || runs != 1 || !bytes.Equal(password, make([]byte, len(password))) {
				t.Fatalf("first connect = code %d runs %d password-cleared %t", code, runs, bytes.Equal(password, make([]byte, len(password))))
			}
			if runError && stdout.Len() != 0 || !runError && !strings.Contains(stdout.String(), "已连接") {
				t.Fatalf("first connect success output disagrees with runtime result: %q", stdout.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestFirstConnectTransportFailureDoesNotSolicitPassword(t *testing.T) {
	dependencies := firstConnectDependencies(t)
	dependencies.loadTransport = func(string) (authstore.TransportProfile, error) {
		return authstore.TransportProfile{}, errors.New(clientFixtureSecret)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"connect", "-n", "210", "--password-stdin"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
	if code != exitFailure || stdout.Len() != 0 || !strings.Contains(stderr.String(), "无法读取传输公开参数") || strings.Contains(stderr.String(), "密码:") {
		t.Fatalf("invalid transport = code %d, output %q / %q", code, stdout.String(), stderr.String())
	}
	assertClientOutputSafe(t, &stdout, &stderr)
}

func TestLogoutStopsRuntimeBeforeRemovingSession(t *testing.T) {
	for _, stopFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "stop-failure"}[stopFailure], func(t *testing.T) {
			dependencies := clientCommandDependencies(t)
			var calls []string
			dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
				calls = append(calls, request.Command)
				if request.Command != "stop" {
					t.Fatal("logout did not stop the runtime")
				}
				if stopFailure {
					return clientruntime.Status{}, errors.New(clientFixtureSecret)
				}
				return clientruntime.Status{}, nil
			}
			dependencies.logoutSession = func(_ context.Context, directory string, stop func() error) error {
				if directory != filepath.Join("private", "test-config") {
					t.Fatal("logout used unexpected session directory")
				}
				if err := stop(); err != nil {
					return err
				}
				calls = append(calls, "remove-session")
				return nil
			}
			dependencies.loadSession = func(string) (clientapi.Session, error) {
				t.Fatal("logout unnecessarily read private session data")
				return clientapi.Session{}, nil
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"logout"}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			expectedCalls, expectedCode := []string{"stop", "remove-session"}, 0
			if stopFailure {
				expectedCalls, expectedCode = []string{"stop"}, exitFailure
			}
			if code != expectedCode || !reflect.DeepEqual(calls, expectedCalls) || stopFailure && stdout.Len() != 0 || !stopFailure && !strings.Contains(stdout.String(), "清除本地登录会话") {
				t.Fatalf("logout = code %d calls %v output %q", code, calls, stdout.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}

func TestStatusSeparatesCachedSessionFromRunningProxyWithoutToken(t *testing.T) {
	for _, cached := range []bool{false, true} {
		for _, asJSON := range []bool{false, true} {
			name := map[bool]string{false: "no-session", true: "cached-session"}[cached] + map[bool]string{false: "-text", true: "-json"}[asJSON]
			t.Run(name, func(t *testing.T) {
				dependencies := clientCommandDependencies(t)
				dependencies.runtimeCall = func(_ context.Context, _ string, request clientruntime.Request) (clientruntime.Status, error) {
					if request.Command != "status" {
						t.Fatal("status used unexpected runtime command")
					}
					return clientruntime.Status{}, clientruntime.ErrNotRunning
				}
				dependencies.loadSession = func(string) (clientapi.Session, error) {
					if !cached {
						return clientapi.Session{}, errors.New(clientFixtureSecret)
					}
					return clientFixtureSession(), nil
				}
				args := []string{"status"}
				if asJSON {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("status = code %d, %q", code, stderr.String())
				}
				if asJSON {
					var state struct {
						Running       bool `json:"running"`
						Connected     bool `json:"connected"`
						SessionCached bool `json:"session_cached"`
					}
					if json.Unmarshal(stdout.Bytes(), &state) != nil || state.Running || state.Connected || state.SessionCached != cached {
						t.Fatalf("status JSON = %q", stdout.String())
					}
				} else {
					message := "无可读会话"
					if cached {
						message = "服务端有效性须刷新确认"
					}
					if !strings.Contains(stdout.String(), message) || !strings.Contains(stdout.String(), "代理未运行") {
						t.Fatalf("status text = %q", stdout.String())
					}
				}
				assertClientOutputSafe(t, &stdout, &stderr)
			})
		}
	}
}

func TestClientCommandParameterErrorsNeverEchoSensitiveArguments(t *testing.T) {
	for _, args := range [][]string{
		{"nodes", "--password=" + clientFixtureSecret},
		{"connect", "--password=" + clientFixtureSecret},
		{"switch", "--password-stdin=" + clientFixtureSecret},
		{"status", "--json=" + clientFixtureSecret},
		{"logout", clientFixtureSecret},
		{"nodes", "--node", "210", clientFixtureSecret},
		{"connect", "210", clientFixtureSecret},
	} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, forbiddenClientInput{t}, &stdout, &stderr, cliDependencies{})
		if code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("invalid command = code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
		}
		assertClientOutputSafe(t, &stdout, &stderr)
	}
}

func TestClientTerminalOutputRemovesControlAndBidiCharacters(t *testing.T) {
	const controls = "\x1b\t\n\r\x00\u202e\u2066\u2069\u2028\u2029"
	for _, command := range []string{"nodes", "status"} {
		t.Run(command, func(t *testing.T) {
			dependencies := clientCommandDependencies(t)
			dependencies.loadSession = func(string) (clientapi.Session, error) {
				session := clientFixtureSession()
				session.Nodes = []clientapi.Node{{ID: "safe-id" + controls, Title: "安全标题" + controls, Status: "安全状态" + controls}}
				return session, nil
			}
			if command == "status" {
				dependencies.runtimeCall = func(context.Context, string, clientruntime.Request) (clientruntime.Status, error) {
					return clientruntime.Status{
						Running: true, Connected: true, NodeID: "safe-id" + controls, NodeTitle: "安全标题" + controls,
						ListenAddress: "127.0.0.1:1080" + controls, ExitIP: "192.0.2.1" + controls,
					}, nil
				}
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{command}, forbiddenClientInput{t}, &stdout, &stderr, dependencies)
			if code != 0 || !strings.Contains(stdout.String(), "安全标题") || stderr.Len() != 0 {
				t.Fatalf("terminal output = code %d, %q / %q", code, stdout.String(), stderr.String())
			}
			for _, unsafe := range []rune{'\x1b', '\r', '\x00', '\u202e', '\u2066', '\u2069', '\u2028', '\u2029'} {
				if strings.ContainsRune(stdout.String(), unsafe) {
					t.Fatalf("terminal output contains unsafe rune U+%04X", unsafe)
				}
			}
			// Tabs and newlines are intentional table/line separators. Their
			// counts must be independent of the supplied node field values.
			wantTabs, wantNewlines := 0, 5
			if command == "nodes" {
				wantTabs, wantNewlines = 10, 3
			}
			if strings.Count(stdout.String(), "\t") != wantTabs || strings.Count(stdout.String(), "\n") != wantNewlines {
				t.Fatalf("untrusted fields changed terminal layout: %q", stdout.String())
			}
			assertClientOutputSafe(t, &stdout, &stderr)
		})
	}
}
