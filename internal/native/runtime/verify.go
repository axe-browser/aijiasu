package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultVerifyURL = "https://myip.ipip.net"

func validateVerifyURL(address string) error {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return errors.New("exit verification requires an HTTPS URL")
	}
	return nil
}

func verifyExitIP(ctx context.Context, engine proxyEngine, address string) (string, error) {
	if err := validateVerifyURL(address); err != nil {
		return "", err
	}
	operation, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: func(dialContext context.Context, network, target string) (net.Conn, error) {
		// net/http can detach its dial context from a request. Retain the
		// verification operation's cancellation for in-flight engine dials.
		dial, cancelDial := context.WithCancel(dialContext)
		stop := context.AfterFunc(operation, cancelDial)
		defer stop()
		defer cancelDial()
		return engine.DialContext(dial, network, target)
	}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(operation, http.MethodGet, address, nil)
	if err != nil {
		return "", errors.New("cannot create exit verification request")
	}
	request.Close = true
	response, err := client.Do(request)
	if err != nil {
		return "", safeFailure("HTTPS exit verification failed", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("HTTPS exit verification returned an invalid status")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return "", errors.New("HTTPS exit verification response is invalid")
	}
	for _, token := range strings.FieldsFunc(string(data), func(c rune) bool {
		return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':')
	}) {
		if ip := net.ParseIP(token); ip != nil {
			return ip.String(), nil
		}
		if ip := net.ParseIP(strings.Trim(token, ":")); ip != nil {
			return ip.String(), nil
		}
	}
	return "", errors.New("HTTPS exit verification did not return an IP address")
}
