package clientapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestLoginDiagnosticIsTypedBoundedAndDoesNotRenderCauses(t *testing.T) {
	const private = "PRIVATE_SYNTHETIC_CAUSE_URL_PASSWORD_AND_RESPONSE"
	for _, test := range []struct {
		name string
		err  error
		want LoginDiagnostic
	}{
		{"auth", ErrAuthRejected, LoginDiagnostic{Code: "auth_rejected"}},
		{"TLS", ErrTLSVerification, LoginDiagnostic{Code: "tls_verification"}},
		{"timeout", context.DeadlineExceeded, LoginDiagnostic{Code: "timeout"}},
		{"DNS", &net.DNSError{Name: private, Err: private, IsNotFound: true}, LoginDiagnostic{Code: "dns_failure"}},
		{"DNS timeout", &net.DNSError{Name: private, Err: private, IsTimeout: true}, LoginDiagnostic{Code: "timeout"}},
		{"network", safeRequestError(context.Background(), errors.New(private)), LoginDiagnostic{Code: "network_failure"}},
		{"HTTP", &HTTPStatusError{StatusCode: 401}, LoginDiagnostic{Code: "http_status", HTTPStatus: 401}},
		{"HTTP invalid low", &HTTPStatusError{StatusCode: 99}, LoginDiagnostic{Code: "unknown"}},
		{"HTTP invalid high", &HTTPStatusError{StatusCode: 600}, LoginDiagnostic{Code: "unknown"}},
		{"HTTP successful", &HTTPStatusError{StatusCode: 200}, LoginDiagnostic{Code: "unknown"}},
		{"response", ErrInvalidResponse, LoginDiagnostic{Code: "invalid_response"}},
		{"response limit", ErrResponseTooLarge, LoginDiagnostic{Code: "invalid_response"}},
		{"unknown", errors.New(private), LoginDiagnostic{Code: "unknown"}},
		{"canceled", context.Canceled, LoginDiagnostic{Code: "canceled"}},
		{"nil", nil, LoginDiagnostic{Code: "unknown"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.err
			if err != nil {
				err = fmt.Errorf("%s: %w", private, errors.Join(err, errors.New(private)))
			}
			if got := DiagnoseLoginError(err); got != test.want {
				t.Fatalf("diagnostic = %+v, want %+v", got, test.want)
			}
		})
	}
	if got := (&HTTPStatusError{StatusCode: 503}).Error(); got != "login returned HTTP status 503" {
		t.Fatalf("HTTP error text changed: %q", got)
	}
}

func TestLoginNetworkMarkerPreservesOriginalCauseAndSafeText(t *testing.T) {
	original := errors.New("PRIVATE_SYNTHETIC_TRANSPORT_DIAGNOSTIC")
	err := safeRequestError(context.Background(), original)
	if !errors.Is(err, original) || !errors.Is(err, ErrNetworkFailure) || err.Error() != "login request failed" {
		t.Fatal("network error lost safe text, classification, or original cause")
	}
}
