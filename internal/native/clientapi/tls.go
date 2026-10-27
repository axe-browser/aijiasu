package clientapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"
)

var ErrTLSPinMismatch = errors.New("TLS certificate public key pin mismatch")

// configureTLSPinning installs an explicit alternative identity policy for this
// client's single HTTPS endpoint. Enrollment is a caller decision: observing a
// certificate on an untrusted connection is not evidence that its pin is trusted.
func configureTLSPinning(client *http.Client, endpoint *url.URL, pinText string) error {
	if pinText == "" {
		return nil
	}
	if len(pinText) != sha256.Size*2 {
		return errors.New("TLS public key pin must contain exactly 64 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(pinText)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("TLS public key pin must contain exactly 64 hexadecimal characters")
	}
	var pin [sha256.Size]byte
	copy(pin[:], decoded)
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok || transport == nil {
		return errors.New("TLS pinning requires a standard HTTP transport")
	}
	if transport.DialTLS != nil || transport.DialTLSContext != nil {
		return errors.New("TLS pinning cannot use a custom TLS dialer")
	}
	owned := transport.Clone()
	configuration := &tls.Config{}
	if transport.TLSClientConfig != nil {
		configuration = transport.TLSClientConfig.Clone()
	}
	if configuration.MinVersion < tls.VersionTLS12 {
		configuration.MinVersion = tls.VersionTLS12
	}
	if configuration.MaxVersion != 0 && configuration.MaxVersion < configuration.MinVersion {
		return errors.New("TLS pinning requires TLS version 1.2 or later")
	}
	configuration.ServerName = endpoint.Hostname()
	previousPeerVerifier := configuration.VerifyPeerCertificate
	if previousPeerVerifier != nil {
		configuration.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			if err := previousPeerVerifier(raw, chains); err != nil {
				return pinnedTLSFailure("additional TLS certificate verification failed", err)
			}
			return nil
		}
	}
	previousConnectionVerifier := configuration.VerifyConnection
	// A fresh cache prevents sessions authenticated under another endpoint or
	// pin policy from being imported. VerifyConnection also runs on resumptions.
	if configuration.ClientSessionCache != nil {
		configuration.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	}
	configuration.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil || len(state.PeerCertificates[0].RawSubjectPublicKeyInfo) == 0 {
			return pinnedTLSFailure("TLS peer certificate is missing", nil)
		}
		leaf := state.PeerCertificates[0]
		actual := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(actual[:], pin[:]) != 1 {
			return pinnedTLSFailure("TLS certificate public key pin mismatch", ErrTLSPinMismatch)
		}
		now := time.Now()
		if !leaf.NotAfter.After(leaf.NotBefore) || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return pinnedTLSFailure("TLS peer certificate is not currently valid", nil)
		}
		if previousConnectionVerifier != nil {
			if err := previousConnectionVerifier(state); err != nil {
				return pinnedTLSFailure("additional TLS connection verification failed", err)
			}
		}
		return nil
	}
	// Standard CA/hostname verification would reject the legacy self-signed
	// localhost certificate before VerifyConnection. It is replaced only here by
	// the configured SPKI pin plus current validity, never by an accept-all mode.
	configuration.InsecureSkipVerify = true
	// Authentication requests are infrequent. Fresh HTTP/1 connections ensure
	// validity and pin checks run again instead of reusing a pre-expiry TLS pool.
	owned.DisableKeepAlives = true
	owned.ForceAttemptHTTP2 = false
	owned.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	owned.Protocols = protocols
	configuration.NextProtos = []string{"http/1.1"}
	owned.TLSClientConfig = configuration
	client.Transport = owned
	return nil
}

func pinnedTLSFailure(message string, cause error) error {
	return &safeOperationError{message: message, cause: errors.Join(ErrTLSVerification, cause)}
}
