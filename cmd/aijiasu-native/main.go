package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/bootstrap"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
	clientruntime "aijiasu-native/internal/native/runtime"
)

const (
	maxPasswordBytes = 4 * 1024
	exitFailure      = 1
	exitUsage        = 2
	exitCancelled    = 130
)

var version = "dev"

var (
	errPasswordEmpty   = errors.New("password is empty")
	errPasswordTooLong = errors.New("password input exceeds limit")
)

type loginClient interface {
	Login(context.Context, string, []byte) (clientapi.Session, error)
}

type cliDependencies struct {
	initialize           func(context.Context, bootstrap.Options) (bootstrap.Result, error)
	defaultDirectory     func() (string, error)
	loadProfile          func(string) (clientapi.Profile, error)
	newClient            func(clientapi.Config) (loginClient, error)
	beginLogin           func(context.Context, string) (authstore.LoginVersion, error)
	saveLoginSession     func(context.Context, string, authstore.LoginVersion, clientapi.Session) error
	sessionVersion       func(context.Context, string, clientapi.Session) (authstore.SessionVersion, error)
	saveRefreshedSession func(context.Context, string, authstore.SessionVersion, clientapi.Session) error
	readPassword         func(context.Context) ([]byte, error)
	loadSession          func(string) (clientapi.Session, error)
	logoutSession        func(context.Context, string, func() error) error
	loadTransport        func(string) (authstore.TransportProfile, error)
	newSyncClient        func(clientapi.Config) (syncClient, error)
	runtimeCall          func(context.Context, string, clientruntime.Request) (clientruntime.Status, error)
	runtimeRun           func(context.Context, clientruntime.Config, string, func(clientruntime.Status)) error
	loadNodeState        func(context.Context, string, string) (nodemgr.State, error)
	setFavorite          func(context.Context, string, string, string, bool) error
	saveLatencies        func(context.Context, string, string, []nodemgr.Latency) error
	probeNodes           func(context.Context, []clientapi.Node, nodemgr.ProbeConfig) ([]nodemgr.Latency, error)
}

func defaultDependencies() cliDependencies {
	return cliDependencies{
		initialize:       bootstrap.Initialize,
		defaultDirectory: authstore.DefaultDirectory,
		loadProfile:      authstore.LoadProfile,
		newClient: func(config clientapi.Config) (loginClient, error) {
			return clientapi.NewClient(config)
		},
		beginLogin:           authstore.BeginLoginContext,
		saveLoginSession:     authstore.SaveLoginSessionContext,
		sessionVersion:       authstore.VersionOfSessionContext,
		saveRefreshedSession: authstore.SaveRefreshedSessionContext,
		readPassword:         readTerminalPassword,
		loadSession:          authstore.LoadSession,
		logoutSession:        authstore.LogoutSessionAfterStopContext,
		loadTransport:        authstore.LoadTransportProfile,
		newSyncClient:        func(config clientapi.Config) (syncClient, error) { return clientapi.NewClient(config) },
		runtimeCall:          clientruntime.Call,
		runtimeRun:           clientruntime.Run,
		loadNodeState:        nodemgr.LoadContext,
		setFavorite:          nodemgr.SetFavoriteContext,
		saveLatencies:        nodemgr.SaveLatenciesContext,
		probeNodes:           nodemgr.Probe,
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, defaultDependencies())
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, dependencies cliDependencies) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}
	switch args[0] {
	case "help", "-h", "--help":
		if len(args) == 2 && args[0] == "help" {
			switch args[1] {
			case "login":
				printLoginHelp(stdout)
				return 0
			case "init":
				printInitHelp(stdout)
				return 0
			case "nodes", "list", "refresh", "connect", "switch", "disconnect", "status", "stop", "logout", "probe", "recent", "favorites", "favorite":
				printClientHelp(stdout, args[1])
				return 0
			}
		}
		if len(args) != 1 {
			fmt.Fprintln(stderr, "帮助参数无效，请运行 aijiasu-native help。")
			return exitUsage
		}
		printHelp(stdout)
		return 0
	case "version", "--version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "版本命令不接受其他参数。")
			return exitUsage
		}
		fmt.Fprintln(stdout, "aijiasu-native "+version)
		return 0
	case "login":
		return runLogin(ctx, args[1:], stdin, stdout, stderr, dependencies)
	case "init":
		return runInit(ctx, args[1:], stdout, stderr, dependencies)
	case "nodes", "list", "refresh", "connect", "switch", "disconnect", "status", "logout", "stop", "probe", "recent", "favorites", "favorite":
		return runClientCommand(ctx, args[0], args[1:], stdin, stdout, stderr, dependencies)
	default:
		fmt.Fprintln(stderr, "未知命令，请运行 aijiasu-native help。")
		return exitUsage
	}
}

func runLogin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, dependencies cliDependencies) int {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	// Flag errors can include user input. Render only fixed messages below.
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	var username, profilePath, configDirectory, tlsPin string
	var passwordStdin bool
	var argumentPassword []byte
	var passwordProvided bool
	defer func() { clear(argumentPassword) }()
	parsePassword := func(value string) error {
		if passwordProvided {
			return errors.New("password argument may only be provided once")
		}
		passwordProvided = true
		if len(value) > maxPasswordBytes {
			return errors.New("password argument exceeds limit")
		}
		argumentPassword = []byte(value)
		return nil
	}
	flags.StringVar(&username, "u", "", "账号")
	flags.StringVar(&username, "username", "", "账号")
	flags.Func("p", "登录密码", parsePassword)
	flags.Func("password", "登录密码", parsePassword)
	flags.BoolVar(&passwordStdin, "password-stdin", false, "从标准输入读取一行密码")
	flags.StringVar(&profilePath, "profile", "", "私密兼容配置文件")
	flags.StringVar(&tlsPin, "tls-pin", "", "登录服务公钥 SHA-256 指纹，64 位十六进制")
	flags.StringVar(&configDirectory, "config-dir", "", "本地配置与会话目录")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printLoginHelp(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "登录参数无效，请运行 aijiasu-native login --help 查看密码选项及长度限制。")
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "登录不接受位置参数；请使用 -u 指定账号，用 -p、交互输入或 --password-stdin 提供密码。")
		return exitUsage
	}
	if passwordProvided && passwordStdin {
		fmt.Fprintln(stderr, "-p/--password 与 --password-stdin 不能同时使用。")
		return exitUsage
	}
	if strings.TrimSpace(username) == "" || strings.ContainsAny(username, "\r\n\x00") {
		fmt.Fprintln(stderr, "请使用 -u 或 --username 指定有效账号。")
		return exitUsage
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}
	if configDirectory == "" {
		var err error
		configDirectory, err = dependencies.defaultDirectory()
		if err != nil {
			fmt.Fprintln(stderr, "无法确定用户配置目录，请使用 --config-dir 指定私密目录。")
			return exitFailure
		}
	}
	if profilePath == "" {
		profilePath = filepath.Join(configDirectory, "compatibility.json")
	}
	profile, err := dependencies.loadProfile(profilePath)
	if err != nil {
		fmt.Fprintln(stderr, "无法读取兼容配置，请检查 --profile 路径、文件格式及私密访问权限。")
		return exitFailure
	}
	client, err := dependencies.newClient(clientapi.Config{
		Endpoint:         profile.Endpoint,
		SigningSeed:      profile.SigningSeed,
		CommonParameters: profile.CommonParameters,
		NowMilliseconds:  clientapi.MonotonicMilliseconds,
		TLSSPKISHA256:    configuredTLSPin(profile, tlsPin),
	})
	if err != nil {
		fmt.Fprintln(stderr, "兼容配置或 TLS 公钥指纹无效，无法建立登录客户端。")
		return exitFailure
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}

	if dependencies.beginLogin == nil || dependencies.saveLoginSession == nil {
		fmt.Fprintln(stderr, "无法记录登录操作，请检查本地会话存储。")
		return exitFailure
	}
	loginVersion, err := dependencies.beginLogin(ctx, configDirectory)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		fmt.Fprintln(stderr, "无法记录登录操作，请检查配置目录权限，或稍后重试。")
		return exitFailure
	}
	var password []byte
	if passwordProvided {
		password = argumentPassword
	} else if passwordStdin {
		password, err = readPasswordLineContext(ctx, stdin)
	} else {
		fmt.Fprint(stderr, "密码: ")
		password, err = dependencies.readPassword(ctx)
		fmt.Fprintln(stderr)
	}
	defer clear(password)
	if err != nil {
		switch {
		case errors.Is(err, errTerminalRestore):
			fmt.Fprintln(stderr, "无法恢复终端状态，请关闭并重新打开当前终端。")
		case ctx.Err() != nil || errors.Is(err, context.Canceled):
			return cancelled(stderr)
		case errors.Is(err, errPasswordEmpty):
			fmt.Fprintln(stderr, "密码不能为空。")
		case errors.Is(err, errPasswordTooLong):
			fmt.Fprintln(stderr, "密码输入超过 4 KiB 上限。")
		default:
			fmt.Fprintln(stderr, "无法读取密码；请使用交互终端，或通过 --password-stdin 提供一行密码。")
		}
		return exitFailure
	}
	if len(password) == 0 {
		fmt.Fprintln(stderr, "密码不能为空。")
		return exitFailure
	}
	if len(password) > maxPasswordBytes {
		fmt.Fprintln(stderr, "密码输入超过 4 KiB 上限。")
		return exitFailure
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}
	session, err := client.Login(ctx, username, password)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
			fmt.Fprintln(stderr, "登录请求超时，请检查网络后重试。")
		case ctx.Err() != nil || errors.Is(err, context.Canceled):
			return cancelled(stderr)
		case errors.Is(err, clientapi.ErrAuthRejected):
			fmt.Fprintln(stderr, "登录被拒绝，请检查账号、密码及账户状态。")
		case errors.Is(err, clientapi.ErrInvalidResponse), errors.Is(err, clientapi.ErrResponseTooLarge):
			fmt.Fprintln(stderr, "服务响应格式不兼容，无法确认登录状态。")
		case errors.Is(err, clientapi.ErrTLSVerification):
			fmt.Fprintln(stderr, "登录服务证书验证失败，已停止登录；请检查当前网络或联系服务方。")
		default:
			fmt.Fprintln(stderr, "登录失败，请检查账号、密码、兼容配置及网络后重试。")
		}
		return exitFailure
	}
	if session.LoginToken == "" {
		fmt.Fprintln(stderr, "服务器未返回有效登录会话，未保存登录状态。")
		return exitFailure
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}
	if err := dependencies.saveLoginSession(ctx, configDirectory, loginVersion, session); err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		if errors.Is(err, authstore.ErrSessionChanged) {
			fmt.Fprintln(stderr, "登录期间登录状态已变更，结果未保存；请重新运行命令。")
		} else {
			fmt.Fprintln(stderr, "服务端认证通过，但保存本地会话失败；请检查 --config-dir 目录权限。")
		}
		return exitFailure
	}
	fmt.Fprintln(stdout, "登录成功，会话已保存。")
	if len(session.Nodes) > 0 {
		fmt.Fprintf(stdout, "已同步 %d 个节点，运行 aijiasu-native nodes 查看。\n", len(session.Nodes))
	}
	return 0
}

func readPasswordLineContext(ctx context.Context, reader io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type passwordResult struct {
		password []byte
		err      error
	}
	results := make(chan passwordResult)
	go func() {
		password, err := readPasswordLine(reader)
		select {
		case results <- passwordResult{password: password, err: err}:
		case <-ctx.Done():
			clear(password)
		}
	}()
	select {
	case result := <-results:
		if err := ctx.Err(); err != nil {
			clear(result.password)
			return nil, err
		}
		return result.password, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func readPasswordLine(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("password input is unavailable")
	}
	// Allow the maximum password plus CRLF and one byte proving oversize input.
	buffered := bufio.NewReader(io.LimitReader(reader, maxPasswordBytes+3))
	password, err := buffered.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		clear(password)
		return nil, fmt.Errorf("read password input: %w", err)
	}
	return finishPasswordLine(password)
}

func finishPasswordLine(password []byte) ([]byte, error) {
	if bytes.HasSuffix(password, []byte{'\n'}) {
		password = password[:len(password)-1]
		if bytes.HasSuffix(password, []byte{'\r'}) {
			password = password[:len(password)-1]
		}
	}
	if len(password) == 0 {
		return nil, errPasswordEmpty
	}
	if len(password) > maxPasswordBytes {
		clear(password)
		return nil, errPasswordTooLong
	}
	return password, nil
}

func cancelled(stderr io.Writer) int {
	fmt.Fprintln(stderr, "操作已取消。")
	return exitCancelled
}

func printHelp(writer io.Writer) {
	fmt.Fprintln(writer, `用法: aijiasu-native <命令>

命令:
  init     从已校验参考文件准备私密配置
  login    使用账号密码登录并保存私密会话
  nodes    查看节点；--refresh 从服务端刷新
  refresh  刷新登录状态和节点缓存
  probe    测试节点 TCP 建连延迟并按延迟排序
  favorite add/remove <节点ID>  添加或取消收藏
  favorites 查看收藏节点
  recent   查看最近成功使用的节点
  connect  连接节点并运行本地 SOCKS5/HTTP 代理
  switch   切换节点；未运行时启动代理
  status   查看登录、连接及代理状态
  disconnect 断开节点，保留代理进程待命
  stop     停止代理进程
  logout   停止代理并删除本地登录会话
  help     查看帮助
  version  查看版本

运行 aijiasu-native <命令> --help 查看参数。
connect/switch 首次启动时在前台运行；其他终端可切换或断开节点。
connect/switch --best 按 TCP 建连延迟自动选优。
提供端口可配置的本地 TCP 代理；当前不支持 UDP。`)
}

func printLoginHelp(writer io.Writer) {
	fmt.Fprintln(writer, `用法: aijiasu-native login -u <账号> [选项]

选项:
  -u, --username <账号>   爱加速账号
  -p, --password <密码>   直接提供密码，最多 4 KiB；不能与 --password-stdin 同用
  --password-stdin       从标准输入读取一行密码，最多 4 KiB
  --profile <文件>       仅当前用户可访问的私密兼容配置文件
  --tls-pin <指纹>       明确信任登录服务公钥的 SHA-256（64 位十六进制）
  --config-dir <目录>    本地配置与会话目录

默认交互输入密码且不回显。
-p/--password 中的密码可能出现在终端历史和进程参数中；推荐交互输入或 --password-stdin。
默认使用系统证书验证；--tls-pin 改为校验指定公钥及证书有效期，请先确认指纹来源可信。
默认兼容配置为配置目录中的 compatibility.json；登录后只保存会话，不保存密码。`)
}
