package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/nodemgr"
)

const latencyCacheLifetime = 5 * time.Minute
const maxBestCandidates = 3

type nodeView struct {
	clientapi.Node
	Favorite         bool       `json:"favorite,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	UseCount         uint64     `json:"use_count,omitempty"`
	LatencyMS        *float64   `json:"latency_ms,omitempty"`
	LatencyCheckedAt *time.Time `json:"latency_checked_at,omitempty"`
	Reachable        *bool      `json:"reachable,omitempty"`
	LatencyFresh     bool       `json:"latency_fresh,omitempty"`
	LatencyError     string     `json:"latency_error,omitempty"`
}

func loadNodeState(ctx context.Context, dependencies cliDependencies, directory, account string) (nodemgr.State, error) {
	if err := ctx.Err(); err != nil {
		return nodemgr.State{}, err
	}
	if dependencies.loadNodeState == nil {
		return nodemgr.State{Version: 1, Entries: map[string]nodemgr.Entry{}}, nil
	}
	state, err := dependencies.loadNodeState(ctx, directory, account)
	if state.Entries == nil {
		state.Entries = map[string]nodemgr.Entry{}
	}
	return state, err
}

func filterManagedNodes(nodes []clientapi.Node, state nodemgr.State, options clientOptions) []clientapi.Node {
	result := make([]clientapi.Node, 0, len(nodes))
	for _, node := range nodes {
		entry := state.Entries[node.ID]
		if options.favorites && !entry.Favorite || options.recent && entry.LastUsedAt.IsZero() {
			continue
		}
		result = append(result, node)
	}
	return result
}

func latencyFor(node clientapi.Node, state nodemgr.State) *nodemgr.Latency {
	measurement := state.Entries[node.ID].Latency
	if measurement == nil || measurement.Host != node.Host || measurement.Port != node.TCPPort {
		return nil
	}
	return measurement
}

func freshLatency(measurement *nodemgr.Latency, now time.Time) bool {
	return measurement != nil && !measurement.CheckedAt.IsZero() && !nodemgr.IsFutureLatency(measurement.CheckedAt, now) && now.Sub(measurement.CheckedAt) <= latencyCacheLifetime
}

func sortManagedNodes(nodes []clientapi.Node, state nodemgr.State, by string, now time.Time) {
	if by == "" {
		return
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		switch by {
		case "latency":
			left, right := latencyFor(a, state), latencyFor(b, state)
			leftOK, rightOK := freshLatency(left, now) && left.Reachable, freshLatency(right, now) && right.Reachable
			if leftOK != rightOK {
				return leftOK
			}
			if leftOK && left.Milliseconds != right.Milliseconds {
				return left.Milliseconds < right.Milliseconds
			}
		case "recent":
			left, right := state.Entries[a.ID].LastUsedAt, state.Entries[b.ID].LastUsedAt
			if !left.Equal(right) {
				return left.After(right)
			}
		case "name":
			left, right := strings.ToLower(a.Title), strings.ToLower(b.Title)
			if left != right {
				return left < right
			}
		}
		return a.ID < b.ID
	})
}

func takeNodes(nodes []clientapi.Node, limit int) []clientapi.Node {
	if limit > 0 && len(nodes) > limit {
		return nodes[:limit]
	}
	return nodes
}

func invalidateLatencies(state nodemgr.State, nodes []clientapi.Node) nodemgr.State {
	entries := make(map[string]nodemgr.Entry, len(state.Entries))
	for id, entry := range state.Entries {
		entries[id] = entry
	}
	for _, node := range nodes {
		entry := entries[node.ID]
		entry.Latency = nil
		entries[node.ID] = entry
	}
	state.Entries = entries
	return state
}

func measureNodes(ctx context.Context, nodes []clientapi.Node, state nodemgr.State, options clientOptions, session clientapi.Session, stderr io.Writer, dependencies cliDependencies) (nodemgr.State, error) {
	usable := make([]clientapi.Node, 0, len(nodes))
	seen := map[string]bool{}
	for _, node := range nodes {
		if node.ID != "" && node.Host != "" && node.TCPPort > 0 && node.TCPPort <= 65535 && !seen[node.ID] {
			usable = append(usable, node)
			seen[node.ID] = true
		}
	}
	nodes = usable
	if len(nodes) == 0 {
		return state, nil
	}
	if dependencies.probeNodes == nil || dependencies.saveLatencies == nil {
		return state, errors.New("node measurement unavailable")
	}
	results, err := dependencies.probeNodes(ctx, nodes, nodemgr.ProbeConfig{Timeout: options.probeTimeout, Attempts: 2, Concurrency: options.concurrency, Budget: options.probeBudget})
	if ctx.Err() != nil {
		return state, ctx.Err()
	}
	if err != nil && !errors.Is(err, nodemgr.ErrProbeBudgetExceeded) {
		return state, err
	}
	if len(results) > 0 {
		if saveErr := dependencies.saveLatencies(ctx, options.directory, session.Username, results); saveErr != nil {
			if errors.Is(saveErr, context.Canceled) || errors.Is(saveErr, context.DeadlineExceeded) {
				return state, saveErr
			}
			return state, errors.New("cannot save node measurements")
		}
		committed, loadErr := loadNodeState(ctx, dependencies, options.directory, session.Username)
		if loadErr != nil {
			return state, fmt.Errorf("cannot reload saved node measurements: %w", loadErr)
		}
		// Another probe may have already committed a newer result. Reconcile only
		// measured IDs, preserving forced-probe invalidation for unmeasured nodes.
		now := time.Now()
		for _, result := range results {
			entry := committed.Entries[result.ID]
			entry.ID = result.ID
			if !nodemgr.IsFutureLatency(result.CheckedAt, now) && (entry.Latency == nil || nodemgr.IsFutureLatency(entry.Latency.CheckedAt, now) || result.CheckedAt.After(entry.Latency.CheckedAt)) {
				copy := result
				copy.CheckedAt = copy.CheckedAt.UTC()
				entry.Latency = &copy
			}
			state.Entries[result.ID] = entry
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "已到测速时限，保留已完成结果；未测节点不会被当作可达。")
	}
	return state, nil
}

func runNodeList(ctx context.Context, command string, options clientOptions, session clientapi.Session, nodes []clientapi.Node, state nodemgr.State, stdout, stderr io.Writer, dependencies cliDependencies) int {
	if command == "recent" && options.limit == 0 {
		options.limit = 20
	}
	if options.sortBy == "" {
		if command == "probe" {
			options.sortBy = "latency"
		} else if options.recent {
			options.sortBy = "recent"
		}
	}
	if options.testLatency {
		var err error
		// Choose bounded probe candidates in the requested order. Latency must
		// still be sorted after this round, rather than by the cache being replaced.
		if options.sortBy != "latency" {
			sortManagedNodes(nodes, state, options.sortBy, time.Now())
		}
		nodes = takeNodes(nodes, options.limit)
		state = invalidateLatencies(state, nodes)
		state, err = measureNodes(ctx, nodes, state, options, session, stderr, dependencies)
		if err != nil {
			if ctx.Err() != nil {
				return cancelled(stderr)
			}
			fmt.Fprintln(stderr, "节点测速或保存结果失败，请检查网络与私密目录。")
			return exitFailure
		}
	}
	now := time.Now()
	sortManagedNodes(nodes, state, options.sortBy, now)
	nodes = takeNodes(nodes, options.limit)
	views := make([]nodeView, 0, len(nodes))
	for _, node := range nodes {
		entry := state.Entries[node.ID]
		view := nodeView{Node: node, Favorite: entry.Favorite, UseCount: entry.UseCount}
		if !entry.LastUsedAt.IsZero() {
			at := entry.LastUsedAt
			view.LastUsedAt = &at
		}
		if measurement := latencyFor(node, state); measurement != nil {
			at := measurement.CheckedAt
			reachable := measurement.Reachable
			view.LatencyCheckedAt = &at
			view.Reachable = &reachable
			view.LatencyFresh = freshLatency(measurement, now)
			view.LatencyError = measurement.Error
			if reachable {
				ms := measurement.Milliseconds
				view.LatencyMS = &ms
			}
		}
		views = append(views, view)
	}
	if options.json {
		if json.NewEncoder(stdout).Encode(views) != nil {
			return exitFailure
		}
		return 0
	}
	fmt.Fprintf(stdout, "共 %d 个节点（延迟为 TCP 建连耗时，含域名解析）\n", len(views))
	fmt.Fprintln(stdout, "ID\t名称\t状态\tTCP 延迟\t收藏\t最近成功使用")
	for _, view := range views {
		latency := "未测"
		if view.Reachable != nil {
			if !*view.Reachable {
				latency = "不可达"
			} else {
				latency = fmt.Sprintf("%.2f ms", *view.LatencyMS)
			}
			if !view.LatencyFresh {
				latency += "（过期）"
			}
		}
		favorite := ""
		if view.Favorite {
			favorite = "收藏"
		}
		recent := ""
		if view.LastUsedAt != nil {
			recent = view.LastUsedAt.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", terminalText(view.ID), terminalText(view.Title), terminalText(view.Status), latency, favorite, recent)
	}
	return 0
}

func connectionCandidates(ctx context.Context, nodes []clientapi.Node, current string, options clientOptions, session clientapi.Session, stderr io.Writer, dependencies cliDependencies) ([]clientapi.Node, error) {
	if !options.best {
		node, err := chooseNode(takeNodes(nodes, options.limit), current)
		if err != nil {
			return nil, err
		}
		return []clientapi.Node{node}, nil
	}
	valid := make([]clientapi.Node, 0, len(nodes))
	seen := map[string]bool{}
	for _, node := range nodes {
		if node.ID != "" && node.Host != "" && node.TCPPort > 0 && !seen[node.ID] {
			valid = append(valid, node)
			seen[node.ID] = true
		}
	}
	if current != "" && len(valid) > 1 {
		filtered := valid[:0]
		for _, node := range valid {
			if node.ID != current {
				filtered = append(filtered, node)
			}
		}
		valid = filtered
	}
	valid = takeNodes(valid, options.limit)
	state, err := loadNodeState(ctx, dependencies, options.directory, session.Username)
	if err != nil {
		return nil, err
	}
	if options.testLatency {
		state = invalidateLatencies(state, valid)
	}
	var stale []clientapi.Node
	for _, node := range valid {
		cached := latencyFor(node, state)
		if options.testLatency || !freshLatency(cached, time.Now()) || !cached.Reachable {
			stale = append(stale, node)
		}
	}
	state, err = measureNodes(ctx, stale, state, options, session, stderr, dependencies)
	if err != nil {
		return nil, err
	}
	sortManagedNodes(valid, state, "latency", time.Now())
	var candidates []clientapi.Node
	for _, node := range valid {
		measurement := latencyFor(node, state)
		if freshLatency(measurement, time.Now()) && measurement.Reachable {
			candidates = append(candidates, node)
			if len(candidates) == maxBestCandidates {
				break
			}
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("no reachable measured node")
	}
	return candidates, nil
}

func runFavorite(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies cliDependencies) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printClientHelp(stdout, "favorite")
		return 0
	}
	if args[0] == "list" {
		return runClientCommand(ctx, "favorites", args[1:], nil, stdout, stderr, dependencies)
	}
	if args[0] != "add" && args[0] != "remove" {
		fmt.Fprintln(stderr, "收藏操作无效，请使用 favorite add/remove/list。")
		return exitUsage
	}
	flags := flag.NewFlagSet("favorite", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var directory string
	var asJSON bool
	flags.StringVar(&directory, "config-dir", "", "私密目录")
	flags.BoolVar(&asJSON, "json", false, "输出 JSON")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printClientHelp(stdout, "favorite")
			return 0
		}
		fmt.Fprintln(stderr, "收藏参数无效。")
		return exitUsage
	}
	if flags.NArg() != 1 || strings.TrimSpace(flags.Arg(0)) == "" {
		fmt.Fprintln(stderr, "请指定一个完整节点 ID。")
		return exitUsage
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}
	if directory == "" {
		var err error
		directory, err = dependencies.defaultDirectory()
		if err != nil {
			fmt.Fprintln(stderr, "无法确定私密目录。")
			return exitFailure
		}
	}
	session, err := dependencies.loadSession(directory)
	if err != nil {
		fmt.Fprintln(stderr, "请先登录以管理当前账号的收藏。")
		return exitFailure
	}
	id := flags.Arg(0)
	favorite := args[0] == "add"
	if favorite {
		found := false
		for _, node := range session.Nodes {
			if node.ID == id {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintln(stderr, "当前节点列表中没有这个 ID，请先刷新节点。")
			return exitFailure
		}
	}
	if dependencies.setFavorite == nil {
		fmt.Fprintln(stderr, "保存收藏失败，请检查私密目录权限。")
		return exitFailure
	}
	if err := dependencies.setFavorite(ctx, directory, session.Username, id, favorite); err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		fmt.Fprintln(stderr, "保存收藏失败，请检查私密目录权限。")
		return exitFailure
	}
	if asJSON {
		if json.NewEncoder(stdout).Encode(struct {
			ID       string `json:"id"`
			Favorite bool   `json:"favorite"`
		}{id, favorite}) != nil {
			return exitFailure
		}
	} else if favorite {
		fmt.Fprintln(stdout, "已收藏节点。")
	} else {
		fmt.Fprintln(stdout, "已取消收藏。")
	}
	return 0
}
