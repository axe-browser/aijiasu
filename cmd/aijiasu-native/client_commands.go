package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	clientruntime "aijiasu-native/internal/native/runtime"
)

type syncClient interface {
	Refresh(context.Context, clientapi.Session) (clientapi.Session, error)
}

type clientOptions struct {
	tlsPin                                                      string
	directory, profile, transport, listen, node, province, city string
	refresh, json, passwordStdin                                bool
	testLatency, favorites, recent, best                        bool
	sortBy                                                      string
	limit, concurrency                                          int
	probeTimeout, probeBudget                                   time.Duration
}

func parseClientOptions(command string, args []string) (clientOptions, error) {
	var options clientOptions
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.directory, "config-dir", "", "私密配置目录")
	flags.BoolVar(&options.json, "json", false, "输出 JSON")
	if isNodeCommand(command) {
		flags.StringVar(&options.profile, "profile", "", "私密兼容配置")
		flags.StringVar(&options.tlsPin, "tls-pin", "", "登录服务公钥 SHA-256 指纹")
		flags.BoolVar(&options.refresh, "refresh", command == "refresh", "刷新节点")
		flags.StringVar(&options.node, "n", "", "节点 ID 或名称")
		flags.StringVar(&options.node, "node", "", "节点 ID 或名称")
		// The reference exposes title text, not structured province/city fields.
		flags.StringVar(&options.province, "p", "", "节点名称包含的省份")
		flags.StringVar(&options.city, "c", "", "节点名称包含的城市")
		flags.BoolVar(&options.favorites, "favorites", command == "favorites", "仅收藏节点")
		flags.BoolVar(&options.recent, "recent", command == "recent", "仅最近使用节点")
		flags.BoolVar(&options.testLatency, "test", command == "probe", "测试 TCP 建连延迟")
		flags.StringVar(&options.sortBy, "sort", "", "latency/name/recent/id")
		flags.IntVar(&options.limit, "limit", 0, "结果或候选数量上限，0 为全部")
		flags.IntVar(&options.concurrency, "concurrency", 8, "测速并发数")
		flags.DurationVar(&options.probeTimeout, "timeout", 2*time.Second, "单次测速超时")
		flags.DurationVar(&options.probeBudget, "budget", 30*time.Second, "测速总时限")
	}
	if command == "connect" || command == "switch" {
		flags.StringVar(&options.transport, "transport", "", "传输公开参数配置")
		flags.StringVar(&options.listen, "listen", "127.0.0.1:1080", "本地代理地址")
		flags.BoolVar(&options.passwordStdin, "password-stdin", false, "从标准输入读取连接密码")
		flags.BoolVar(&options.best, "best", false, "按 TCP 建连延迟自动选优")
	}
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() > 1 || (flags.NArg() == 1 && (!isNodeCommand(command) || options.node != "")) {
		return options, errors.New("invalid positional argument")
	}
	if flags.NArg() == 1 {
		options.node = flags.Arg(0)
	}
	if isNodeCommand(command) && (options.limit < 0 || options.limit > 10000 || options.concurrency < 1 || options.concurrency > 64 ||
		options.probeTimeout <= 0 || options.probeTimeout > 30*time.Second || options.probeBudget <= 0 || options.probeBudget > 5*time.Minute) {
		return options, errors.New("invalid node management limits")
	}
	switch options.sortBy {
	case "", "latency", "name", "recent", "id":
	default:
		return options, errors.New("invalid node sort")
	}
	return options, nil
}

func isNodeCommand(command string) bool {
	switch command {
	case "nodes", "list", "refresh", "connect", "switch", "probe", "recent", "favorites":
		return true
	}
	return false
}

func runClientCommand(ctx context.Context, command string, args []string, stdin io.Reader, stdout, stderr io.Writer, dependencies cliDependencies) int {
	if command == "favorite" {
		return runFavorite(ctx, args, stdout, stderr, dependencies)
	}
	options, err := parseClientOptions(command, args)
	if errors.Is(err, flag.ErrHelp) {
		printClientHelp(stdout, command)
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "命令参数无效，请运行对应命令的 --help；不要把密码写入参数。")
		return exitUsage
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}
	if options.directory == "" {
		options.directory, err = dependencies.defaultDirectory()
		if err != nil {
			fmt.Fprintln(stderr, "无法确定用户配置目录，请使用 --config-dir 指定。")
			return exitFailure
		}
	}
	if options.profile == "" {
		options.profile = filepath.Join(options.directory, "compatibility.json")
	}
	if options.transport == "" {
		options.transport = filepath.Join(options.directory, "transport.json")
	}
	switch command {
	case "status", "disconnect", "stop", "logout":
		return runControlCommand(ctx, command, options, stdout, stderr, dependencies)
	}
	session, err := dependencies.loadSession(options.directory)
	if err != nil {
		fmt.Fprintln(stderr, "无法读取登录会话，请先运行 login，并检查配置目录权限。")
		return exitFailure
	}
	if options.refresh || session.Nodes == nil || ((command == "connect" || command == "switch") && session.ServiceUsername == "") {
		session, err = refreshSession(ctx, options, session, dependencies)
		if err != nil {
			return reportRefreshFailure(ctx, stderr, err)
		}
	}
	nodes := filterNodes(session.Nodes, options)
	state, err := loadNodeState(ctx, dependencies, options.directory, session.Username)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		fmt.Fprintln(stderr, "无法读取节点管理记录，请检查私密目录和文件权限。")
		return exitFailure
	}
	nodes = filterManagedNodes(nodes, state, options)
	if command != "connect" && command != "switch" {
		return runNodeList(ctx, command, options, session, nodes, state, stdout, stderr, dependencies)
	}
	return runConnectCommand(ctx, command, options, session, nodes, stdin, stdout, stderr, dependencies)
}

func refreshSession(ctx context.Context, options clientOptions, session clientapi.Session, dependencies cliDependencies) (clientapi.Session, error) {
	profile, err := dependencies.loadProfile(options.profile)
	if err != nil {
		return clientapi.Session{}, errors.New("cannot load synchronization profile")
	}
	client, err := dependencies.newSyncClient(clientapi.Config{
		Endpoint: profile.Endpoint, SigningSeed: profile.SigningSeed,
		CommonParameters: profile.CommonParameters, NowMilliseconds: clientapi.MonotonicMilliseconds,
		TLSSPKISHA256: configuredTLSPin(profile, options.tlsPin),
	})
	if err != nil {
		return clientapi.Session{}, errors.New("invalid synchronization profile")
	}
	if dependencies.sessionVersion == nil || dependencies.saveRefreshedSession == nil {
		return clientapi.Session{}, errors.New("conditional session storage is unavailable")
	}
	version, err := dependencies.sessionVersion(ctx, options.directory, session)
	if err != nil {
		return clientapi.Session{}, fmt.Errorf("cannot capture login session version: %w", err)
	}
	updated, err := client.Refresh(ctx, session)
	if err != nil {
		return clientapi.Session{}, err
	}
	if err := ctx.Err(); err != nil {
		return clientapi.Session{}, err
	}
	if err := dependencies.saveRefreshedSession(ctx, options.directory, version, updated); err != nil {
		return clientapi.Session{}, fmt.Errorf("cannot save refreshed session: %w", err)
	}
	return updated, nil
}

func reportRefreshFailure(ctx context.Context, stderr io.Writer, err error) int {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return cancelled(stderr)
	}
	switch {
	case errors.Is(err, authstore.ErrSessionChanged):
		fmt.Fprintln(stderr, "刷新期间登录状态已变更，结果未保存；请重新运行命令。")
	case errors.Is(err, clientapi.ErrTLSVerification):
		fmt.Fprintln(stderr, "刷新失败：登录服务证书验证失败，已停止请求。")
	case errors.Is(err, clientapi.ErrAuthRejected):
		fmt.Fprintln(stderr, "刷新被拒绝，请重新登录后再试。")
	default:
		fmt.Fprintln(stderr, "刷新节点失败，请检查网络、登录状态及兼容配置；原会话未被覆盖。")
	}
	return exitFailure
}

func filterNodes(nodes []clientapi.Node, options clientOptions) []clientapi.Node {
	result := make([]clientapi.Node, 0)
	exactID := ""
	for _, node := range nodes {
		if options.node != "" && node.ID == options.node {
			exactID = node.ID
			break
		}
	}
	for _, node := range nodes {
		title := strings.ToLower(node.Title)
		if (exactID != "" && node.ID != exactID) || (exactID == "" && options.node != "" && !strings.Contains(title, strings.ToLower(options.node))) ||
			!strings.Contains(title, strings.ToLower(options.province)) || !strings.Contains(title, strings.ToLower(options.city)) {
			continue
		}
		result = append(result, node)
	}
	return result
}

func chooseNode(nodes []clientapi.Node, current string) (clientapi.Node, error) {
	var candidates []clientapi.Node
	seen := make(map[string]bool)
	for _, node := range nodes {
		if node.ID != "" && node.Host != "" && node.TCPPort > 0 && !seen[node.ID] {
			candidates = append(candidates, node)
			seen[node.ID] = true
		}
	}
	if len(candidates) > 1 && current != "" {
		filtered := make([]clientapi.Node, 0, len(candidates))
		for _, node := range candidates {
			if node.ID != current {
				filtered = append(filtered, node)
			}
		}
		candidates = filtered
	}
	if len(candidates) == 0 {
		return clientapi.Node{}, errors.New("no matching TCP node")
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return clientapi.Node{}, errors.New("node selection failed")
	}
	return candidates[index.Int64()], nil
}

func callRuntime(ctx context.Context, dependencies cliDependencies, directory string, request clientruntime.Request) (clientruntime.Status, error) {
	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return dependencies.runtimeCall(callCtx, directory, request)
}

func runConnectCommand(ctx context.Context, command string, options clientOptions, session clientapi.Session, nodes []clientapi.Node, stdin io.Reader, stdout, stderr io.Writer, dependencies cliDependencies) int {
	state, err := callRuntime(ctx, dependencies, options.directory, clientruntime.Request{Command: "status"})
	if err != nil && !errors.Is(err, clientruntime.ErrNotRunning) {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		fmt.Fprintln(stderr, "无法访问代理进程，请检查配置目录和本地控制接口。")
		return exitFailure
	}
	current := ""
	if command == "switch" {
		current = state.NodeID
	}
	candidates, err := connectionCandidates(ctx, nodes, current, options, session, stderr, dependencies)
	if err != nil {
		if ctx.Err() != nil {
			return cancelled(stderr)
		}
		fmt.Fprintln(stderr, "未找到匹配且具有 TCP 连接参数的节点，请运行 nodes --refresh 检查。")
		return exitFailure
	}
	if state.Running {
		for _, node := range candidates {
			state, err = callRuntime(ctx, dependencies, options.directory, clientruntime.Request{Command: command, NodeID: node.ID})
			if err == nil {
				return writeStatus(stdout, state, options.json)
			}
			if ctx.Err() != nil {
				return cancelled(stderr)
			}
		}
		fmt.Fprintln(stderr, "节点连接或切换失败；可运行 status 检查原连接。")
		return exitFailure
	}
	profile, err := dependencies.loadProfile(options.profile)
	if err != nil {
		fmt.Fprintln(stderr, "无法读取兼容配置，请检查文件及权限。")
		return exitFailure
	}
	transport, err := dependencies.loadTransport(options.transport)
	if err != nil {
		fmt.Fprintln(stderr, "无法读取传输公开参数，请先准备 transport.json，并检查文件权限。")
		return exitFailure
	}
	if session.ServiceUsername == "" {
		fmt.Fprintln(stderr, "服务未返回连接所需的规范账号，请重新登录或刷新。")
		return exitFailure
	}
	var password []byte
	if options.passwordStdin {
		password, err = readPasswordLineContext(ctx, stdin)
	} else {
		fmt.Fprintln(stderr, "首次启动代理需要账号密码，仅保留在当前进程内供切换节点使用。")
		fmt.Fprint(stderr, "密码: ")
		password, err = dependencies.readPassword(ctx)
		fmt.Fprintln(stderr)
	}
	defer clear(password)
	if err != nil || len(password) == 0 || len(password) > maxPasswordBytes {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		if errors.Is(err, errTerminalRestore) {
			fmt.Fprintln(stderr, "无法恢复终端状态，请关闭并重新打开当前终端。")
		} else {
			fmt.Fprintln(stderr, "无法读取有效密码，请使用交互终端或 --password-stdin。")
		}
		return exitFailure
	}
	for _, node := range candidates {
		ready := false
		connectionPassword := append([]byte(nil), password...)
		err = dependencies.runtimeRun(ctx, clientruntime.Config{
			Directory: options.directory, Session: session, Profile: profile, Transport: transport,
			Password: connectionPassword, ListenAddress: options.listen,
		}, node.ID, func(state clientruntime.Status) {
			ready = true
			clear(password)
			writeStatus(stdout, state, options.json)
			if !options.json {
				fmt.Fprintln(stdout, "代理在前台运行；按 Ctrl+C 停止，其他终端可运行 switch、disconnect 或 stop。")
			}
		})
		clear(connectionPassword)
		if ctx.Err() != nil && !ready {
			return cancelled(stderr)
		}
		if err != nil && ctx.Err() == nil {
			if ready {
				fmt.Fprintln(stderr, "代理运行中断，请检查网络和节点。")
				return exitFailure
			}
			continue
		}
		// Once running, Ctrl+C is the normal way to stop a foreground proxy.
		return 0
	}
	fmt.Fprintln(stderr, "代理启动失败，已尝试候选节点；请检查节点权限、密码、网络和本地端口。")
	return exitFailure
}

func runControlCommand(ctx context.Context, command string, options clientOptions, stdout, stderr io.Writer, dependencies cliDependencies) int {
	if command == "logout" {
		return runLogoutCommand(ctx, options, stdout, stderr, dependencies)
	}
	state, err := callRuntime(ctx, dependencies, options.directory, clientruntime.Request{Command: command})
	if errors.Is(err, clientruntime.ErrNotRunning) {
		state, err = clientruntime.Status{}, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return cancelled(stderr)
		}
		fmt.Fprintln(stderr, "无法完成代理控制操作，请检查进程及本地控制接口。")
		return exitFailure
	}
	if command == "status" {
		_, sessionErr := dependencies.loadSession(options.directory)
		if options.json {
			result := struct {
				clientruntime.Status
				SessionCached bool `json:"session_cached"`
			}{state, sessionErr == nil}
			if json.NewEncoder(stdout).Encode(result) != nil {
				return exitFailure
			}
			return 0
		}
		if sessionErr == nil {
			fmt.Fprintln(stdout, "本地登录会话：已保存（服务端有效性须刷新确认）")
		} else {
			fmt.Fprintln(stdout, "本地登录会话：无可读会话")
		}
	}
	return writeStatus(stdout, state, options.json)
}

func runLogoutCommand(ctx context.Context, options clientOptions, stdout, stderr io.Writer, dependencies cliDependencies) int {
	stopped := false
	err := dependencies.logoutSession(ctx, options.directory, func() error {
		_, err := callRuntime(ctx, dependencies, options.directory, clientruntime.Request{Command: "stop"})
		if err != nil && !errors.Is(err, clientruntime.ErrNotRunning) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		stopped = true
		return nil
	})
	if err != nil || !stopped {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		if stopped {
			fmt.Fprintln(stderr, "代理已停止，但删除本地会话失败；请检查目录权限。")
		} else {
			fmt.Fprintln(stderr, "无法完成退出登录，请检查配置目录、代理进程及本地控制接口。")
		}
		return exitFailure
	}
	if options.json {
		if json.NewEncoder(stdout).Encode(struct {
			LoggedOut bool `json:"logged_out"`
		}{true}) != nil {
			return exitFailure
		}
		return 0
	}
	fmt.Fprintln(stdout, "已停止代理并清除本地登录会话。")
	return 0
}

func writeStatus(writer io.Writer, state clientruntime.Status, asJSON bool) int {
	if asJSON {
		if json.NewEncoder(writer).Encode(state) != nil {
			return exitFailure
		}
		return 0
	}
	if !state.Running {
		fmt.Fprintln(writer, "代理未运行。")
	} else if !state.Connected {
		fmt.Fprintln(writer, "代理进程待命，节点未连接。")
	} else {
		fmt.Fprintf(writer, "已连接：%s (%s)\n本地 SOCKS5/HTTP：%s\n已验证出口 IP：%s\n活动连接：%d\n", terminalText(state.NodeTitle), terminalText(state.NodeID), terminalText(state.ListenAddress), terminalText(state.ExitIP), state.ActiveConnections)
	}
	if state.LastError != "" {
		fmt.Fprintln(writer, "最近一次连接检查失败，请检查节点或网络。")
	}
	if state.HistoryWarning {
		fmt.Fprintln(writer, "保存最近使用记录失败，请检查私密目录。")
	}
	return 0
}

func terminalText(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return -1
		}
		return r
	}, text)
}

func printClientHelp(writer io.Writer, command string) {
	if command == "favorite" {
		fmt.Fprintln(writer, "用法: aijiasu-native favorite add/remove [--config-dir <目录>] [--json] <完整节点ID>\n      aijiasu-native favorite list [筛选选项]\n\n收藏按账号保存在本机；添加时要求 ID 在当前节点缓存中。")
		return
	}
	fmt.Fprintf(writer, "用法: aijiasu-native %s [选项]\n\n--config-dir <目录>  私密配置与会话目录\n--json              输出 JSON\n", command)
	if isNodeCommand(command) {
		fmt.Fprintln(writer, "--tls-pin <指纹>     刷新时覆盖登录服务公钥指纹；默认仅固定爱加速登录入口使用内置指纹")
		fmt.Fprintln(writer, "--refresh           从服务端刷新登录状态和节点\n--profile <文件>     私密兼容配置\n-n, --node <值>      节点 ID 精确匹配，或名称包含此值\n-p <省份> -c <城市>  按节点名称筛选")
		fmt.Fprintln(writer, "--test              测试 TCP 建连延迟并保存结果\n--sort <方式>        latency/name/recent/id\n--favorites         仅收藏节点\n--recent            仅成功使用过的节点\n--limit <数量>       显示或探测候选上限，0 为全部\n--timeout <时间>     单次建连超时，默认 2s\n--budget <时间>      测速总时限，默认 30s\n--concurrency <数量> 测速并发数，默认 8\n\n延迟是含域名解析的 TCP 建连耗时，2 次成功样本的中位数；不代表带宽或账号连接权限。\n排序优先使用 5 分钟内且地址未变的可达结果；最近使用默认显示 20 个节点。")
	}
	if command == "connect" || command == "switch" {
		fmt.Fprintln(writer, "--best              测速后按延迟选优，至多尝试 3 个可达候选\n--listen <地址>      首次启动时的本地代理地址，默认 127.0.0.1:1080\n--transport <文件>   传输公开参数配置\n--password-stdin     首次启动时从标准输入读取一行密码\n\n默认随机选择；--best 使用有效缓存并探测未测或过期候选，测速超时则使用已完成结果。\n切换时优先避开当前节点；失败保留原连接；成功后才记录最近使用。\n首次启动在前台运行并需要账号密码；之后切换复用进程内密码。\n提供本地 SOCKS5/HTTP TCP 代理；当前不支持 UDP。")
	}
}
