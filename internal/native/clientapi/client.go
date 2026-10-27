package clientapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout = 25 * time.Second
	maxResponseBytes   = 4 << 20
	maxPasswordBytes   = 4 << 10
	loginCommand       = "ClientApiLogin/Login"
)

var (
	ErrAuthRejected     = errors.New("authentication rejected")
	ErrInvalidResponse  = errors.New("invalid login response")
	ErrResponseTooLarge = errors.New("login response exceeds size limit")
	ErrTLSVerification  = errors.New("TLS certificate verification failed")
)

// Profile supplies protocol metadata explicitly; it contains no built-in seed.
type Profile struct {
	Version          int               `json:"version"`
	Endpoint         string            `json:"endpoint"`
	ClientVersion    string            `json:"client_version"`
	SigningSeed      string            `json:"signing_seed"`
	CommonParameters map[string]string `json:"common_parameters"`
	TLSSPKISHA256    string            `json:"tls_spki_sha256,omitempty"`
}

type Config struct {
	Endpoint         string
	SigningSeed      string
	CommonParameters map[string]string
	HTTPClient       *http.Client
	NowMilliseconds  func() (uint64, error)
	TLSSPKISHA256    string
}

// Session retains only reusable authentication state and understood public nodes.
type Session struct {
	Username        string            `json:"username"`
	LoginToken      string            `json:"login_token"`
	AuthenticatedAt time.Time         `json:"authenticated_at"`
	ExpireTime      json.Number       `json:"expire_time,omitempty"`
	ServiceUsername string            `json:"service_username,omitempty"`
	Nodes           []Node            `json:"nodes,omitzero"`
	SyncVersion     map[string]string `json:"sync_version,omitempty"`
}

type Client struct {
	endpoint         string
	signingSeed      string
	commonParameters map[string]string
	httpClient       http.Client
	nowMilliseconds  func() (uint64, error)
}

func NewClient(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery ||
		endpoint.Fragment != "" || strings.Contains(config.Endpoint, "#") || endpoint.Opaque != "" {
		return nil, errors.New("login endpoint must be an HTTPS URL without user information, query, or fragment")
	}
	if config.SigningSeed == "" {
		return nil, errors.New("login signing seed is required")
	}

	parameters := make(map[string]string, len(config.CommonParameters))
	for key, value := range config.CommonParameters {
		if strings.HasPrefix(strings.ToLower(key), "_sync[") {
			return nil, errors.New("common parameters must not contain synchronization fields")
		}
		switch strings.ToLower(key) {
		case "cmd", "username", "password", "_client_login":
			return nil, errors.New("common parameters must not contain authentication fields")
		}
		parameters[key] = value
	}
	for _, key := range []string{"v", "_site", "_lang", "_m", "_os_ver", "_os_dev", "_os_dim", "_uid"} {
		if _, exists := parameters[key]; !exists {
			return nil, fmt.Errorf("common parameter %s is required", key)
		}
	}
	if !isASCIIAlphanumeric(parameters["_uid"]) {
		return nil, errors.New("common parameter _uid must contain only ASCII letters and digits and be nonempty")
	}
	if _, err := EncodeForm(parameters); err != nil {
		return nil, errors.New("common parameters contain an invalid field name")
	}

	var httpClient http.Client
	if config.HTTPClient != nil {
		httpClient = *config.HTTPClient
	}
	if httpClient.Timeout <= 0 {
		httpClient.Timeout = defaultHTTPTimeout
	}
	if err := configureTLSPinning(&httpClient, endpoint, config.TLSSPKISHA256); err != nil {
		return nil, err
	}
	// A login body and its signature must never be replayed to a redirect target.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	nowMilliseconds := config.NowMilliseconds
	if nowMilliseconds == nil {
		nowMilliseconds = MonotonicMilliseconds
	}
	return &Client{
		endpoint:         endpoint.String(),
		signingSeed:      config.SigningSeed,
		commonParameters: parameters,
		httpClient:       httpClient,
		nowMilliseconds:  nowMilliseconds,
	}, nil
}

// Login performs one request. Neither the password nor the raw response is kept
// in the returned session, and server messages are not included in errors.
func (client *Client) Login(ctx context.Context, username string, password []byte) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, safeRequestError(ctx, err)
	}
	if !validAccount(username) {
		return Session{}, errors.New("login username must be nonempty and contain no CR, LF, or NUL")
	}
	if len(password) == 0 {
		return Session{}, errors.New("login username and password are required")
	}
	if len(password) > maxPasswordBytes {
		return Session{}, errors.New("login password exceeds size limit")
	}
	parameters := map[string]string{"username": username, "password": string(password)}
	data, err := client.postAuthenticated(ctx, parameters)
	if err != nil {
		return Session{}, err
	}
	return parseLoginResponse(data, username)
}

// postAuthenticated is shared by password login and token synchronization so
// both use the same signing, redirect, TLS, timeout and response-size policy.
func (client *Client) postAuthenticated(ctx context.Context, authentication map[string]string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, safeRequestError(ctx, err)
	}
	parameters := make(map[string]string, len(client.commonParameters)+len(authentication)+1)
	for key, value := range client.commonParameters {
		parameters[key] = value
	}
	parameters["cmd"] = loginCommand
	for key, value := range authentication {
		parameters[key] = value
	}
	body, err := EncodeForm(parameters)
	if err != nil {
		return nil, errors.New("cannot encode login request")
	}
	timestamp, err := client.nowMilliseconds()
	if err != nil {
		return nil, &safeOperationError{message: "cannot read login timestamp", cause: err}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, strings.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create login request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "*/*")
	request.Header.Set("User-Agent", "")
	request.Header.Del("Expect")
	request.Header.Set("X-Timestamp", strconv.FormatUint(timestamp, 10))
	request.Header.Set("X-Sig", RequestSignature(client.signingSeed, body, timestamp))
	request.Close = true
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, safeRequestError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login returned HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, safeRequestError(ctx, err)
	}
	if len(data) > maxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
		return nil, ErrInvalidResponse
	}
	return data, nil
}

func isASCIIAlphanumeric(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func safeRequestError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return &safeOperationError{message: "login request interrupted", cause: errors.Join(err, ctx.Err())}
	}
	if errors.Is(err, context.Canceled) {
		return &safeOperationError{message: "login request interrupted", cause: err}
	}
	var certificateError *tls.CertificateVerificationError
	if errors.Is(err, ErrTLSVerification) || errors.As(err, &certificateError) {
		return &safeOperationError{
			message: "login TLS certificate verification failed",
			cause:   errors.Join(ErrTLSVerification, err),
		}
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
		return &safeOperationError{message: "login request timed out", cause: errors.Join(err, context.DeadlineExceeded)}
	}
	// Transport errors may contain URLs or data from a custom transport. Do not
	// forward their text, or parse errors that can quote server-controlled input.
	return &safeOperationError{message: "login request failed", cause: err}
}

// Error text is safe for display; diagnostic callers can inspect the cause
// through errors.Is/As without automatically printing server/transport text.
type safeOperationError struct {
	message string
	cause   error
}

func (err *safeOperationError) Error() string { return err.message }

func (err *safeOperationError) Unwrap() error { return err.cause }
