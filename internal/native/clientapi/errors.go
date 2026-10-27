package clientapi

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// HTTPStatusError retains only the status, never the response body or endpoint.
type HTTPStatusError struct {
	StatusCode int
}

func (err *HTTPStatusError) Error() string {
	return fmt.Sprintf("login returned HTTP status %d", err.StatusCode)
}

type LoginDiagnostic struct {
	Code       string
	HTTPStatus int
}

// DiagnoseLoginError exposes a fixed classification without rendering its cause.
func DiagnoseLoginError(err error) LoginDiagnostic {
	diagnostic := LoginDiagnostic{Code: "unknown"}
	var networkError net.Error
	var dnsError *net.DNSError
	var httpError *HTTPStatusError
	switch {
	case errors.Is(err, context.Canceled):
		diagnostic.Code = "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		diagnostic.Code = "timeout"
	case errors.Is(err, ErrAuthRejected):
		diagnostic.Code = "auth_rejected"
	case errors.Is(err, ErrInvalidResponse), errors.Is(err, ErrResponseTooLarge):
		diagnostic.Code = "invalid_response"
	case errors.Is(err, ErrTLSVerification):
		diagnostic.Code = "tls_verification"
	case errors.As(err, &httpError):
		if httpError.StatusCode >= 100 && httpError.StatusCode <= 599 && httpError.StatusCode != 200 {
			diagnostic.Code, diagnostic.HTTPStatus = "http_status", httpError.StatusCode
		}
	case errors.As(err, &dnsError):
		diagnostic.Code = "dns_failure"
	case connectionRefused(err):
		diagnostic.Code = "connection_refused"
	case errors.Is(err, ErrNetworkFailure):
		diagnostic.Code = "network_failure"
	}
	return diagnostic
}
