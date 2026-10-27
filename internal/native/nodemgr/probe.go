package nodemgr

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"aijiasu-native/internal/native/clientapi"
)

const (
	defaultProbeTimeout     = 2 * time.Second
	defaultProbeAttempts    = 2
	defaultProbeConcurrency = 8
	defaultProbeBudget      = 30 * time.Second
	maxProbeNodes           = 10000
	maxProbeIDBytes         = 16 << 10
	maxProbeAttempts        = 10
	maxProbeConcurrency     = 64
	minimumLatencyMS        = 0.001
)

// LatencyFutureTolerance permits small clock corrections while rejecting
// measurements left ahead of the current clock after a substantial rollback.
const LatencyFutureTolerance = time.Minute

// IsFutureLatency identifies timestamps that cannot be reused under this clock.
func IsFutureLatency(checkedAt, now time.Time) bool {
	return checkedAt.After(now.Add(LatencyFutureTolerance))
}

// ErrProbeBudgetExceeded distinguishes the shared probe budget from a caller's
// cancellation or deadline. Budget errors also match context.DeadlineExceeded.
var ErrProbeBudgetExceeded = errors.New("node probe budget exceeded")

type ProbeConfig struct {
	Timeout     time.Duration
	Attempts    int
	Concurrency int
	Budget      time.Duration
	// DialContext must honor its context, as net.Dialer.DialContext does.
	DialContext func(context.Context, string, string) (net.Conn, error)
	Now         func() time.Time
}

type Latency struct {
	ID           string    `json:"id"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	Milliseconds float64   `json:"latency_ms"`
	CheckedAt    time.Time `json:"checked_at"`
	Successes    int       `json:"successes"`
	Attempts     int       `json:"attempts"`
	Reachable    bool      `json:"reachable"`
	Error        string    `json:"error,omitempty"`
}

// Probe measures TCP connection establishment, including name resolution. It
// sends no application data and closes every returned connection immediately.
// Results follow input order. On interruption, only nodes with an attempted
// connection are returned; their Attempts counts may be below the configured
// count. Reachable must be considered before latency: failures have no timing.
func Probe(ctx context.Context, nodes []clientapi.Node, config ProbeConfig) ([]Latency, error) {
	if ctx == nil {
		return nil, errors.New("node probe context is required")
	}
	var err error
	config, err = normalizeProbeConfig(config)
	if err != nil {
		return nil, err
	}
	if err := validateProbeNodes(nodes); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return []Latency{}, err
	}
	if len(nodes) == 0 {
		return []Latency{}, nil
	}
	probeContext, cancel := context.WithTimeout(ctx, config.Budget)
	defer cancel()
	// Serialize injected clocks too, so a simple deterministic test clock need
	// not acquire its own lock when multiple workers finish together.
	var clockMu sync.Mutex
	clock := config.Now
	config.Now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock()
	}
	jobs := make(chan int, len(nodes))
	for index := range nodes {
		jobs <- index
	}
	close(jobs)
	results := make([]Latency, len(nodes))
	measured := make([]bool, len(nodes))
	var workers sync.WaitGroup
	for worker := 0; worker < min(config.Concurrency, len(nodes)); worker++ {
		workers.Go(func() {
			for index := range jobs {
				if probeContext.Err() != nil {
					return
				}
				result := probeNode(probeContext, nodes[index], config)
				if result.Attempts != 0 {
					results[index], measured[index] = result, true
				}
			}
		})
	}
	workers.Wait()
	completed := make([]Latency, 0, len(nodes))
	for index, result := range results {
		if measured[index] {
			completed = append(completed, result)
		}
	}
	if err := ctx.Err(); err != nil {
		return completed, err
	}
	if probeContext.Err() != nil {
		return completed, errors.Join(ErrProbeBudgetExceeded, context.DeadlineExceeded)
	}
	return completed, nil
}

func normalizeProbeConfig(config ProbeConfig) (ProbeConfig, error) {
	if config.Timeout < 0 || config.Budget < 0 || config.Attempts < 0 || config.Concurrency < 0 ||
		config.Attempts > maxProbeAttempts || config.Concurrency > maxProbeConcurrency {
		return ProbeConfig{}, errors.New("invalid node probe limits")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultProbeTimeout
	}
	if config.Budget == 0 {
		config.Budget = defaultProbeBudget
	}
	if config.Attempts == 0 {
		config.Attempts = defaultProbeAttempts
	}
	if config.Concurrency == 0 {
		config.Concurrency = defaultProbeConcurrency
	}
	if config.DialContext == nil {
		config.DialContext = (&net.Dialer{}).DialContext
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config, nil
}

func validateProbeNodes(nodes []clientapi.Node) error {
	if len(nodes) > maxProbeNodes {
		return errors.New("node probe input exceeds size limit")
	}
	seen := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		if node.ID == "" || len(node.ID) > maxProbeIDBytes || strings.TrimSpace(node.ID) != node.ID ||
			strings.ContainsFunc(node.ID, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) ||
			!validProbeHost(node.Host) || node.TCPPort < 1 || node.TCPPort > 65535 {
			return errors.New("node probe input contains an invalid node")
		}
		if seen[node.ID] {
			return errors.New("node probe input contains duplicate identifiers")
		}
		seen[node.ID] = true
	}
	return nil
}

func validProbeHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 254 {
		return false
	}
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func probeNode(ctx context.Context, node clientapi.Node, config ProbeConfig) Latency {
	result := Latency{ID: node.ID, Host: node.Host, Port: node.TCPPort}
	samples := make([]float64, 0, config.Attempts)
	address := net.JoinHostPort(node.Host, strconv.Itoa(node.TCPPort))
	for range config.Attempts {
		if ctx.Err() != nil {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, config.Timeout)
		start := config.Now()
		result.Attempts++
		conn, err := config.DialContext(attempt, "tcp", address)
		end := config.Now()
		if conn != nil {
			_ = conn.Close()
		}
		cancel()
		if err == nil && conn != nil {
			elapsed := max(float64(end.Sub(start))/float64(time.Millisecond), minimumLatencyMS)
			samples = append(samples, elapsed)
		}
	}
	if result.Attempts == 0 {
		return result
	}
	result.CheckedAt = config.Now().UTC()
	result.Successes = len(samples)
	result.Reachable = len(samples) > 0
	if !result.Reachable {
		result.Error = "TCP connection failed"
		if ctx.Err() != nil {
			result.Error = "node probe interrupted"
		}
		return result
	}
	slices.Sort(samples)
	middle := len(samples) / 2
	result.Milliseconds = samples[middle]
	if len(samples)%2 == 0 {
		result.Milliseconds = (samples[middle-1] + samples[middle]) / 2
	}
	return result
}
