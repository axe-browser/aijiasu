package fvproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxControlBodyBytes = 64 << 10
	maxControlFields    = 64
	maxFieldValueBytes  = 4 << 10
	maxOuterReplyBytes  = 4 << 10
)

// The LF map codec is at 0x100082010/0x1000821d0 in macOS 4.9.6.0.
// Bounds and rejection of duplicate fields are local input protections.
func encodeFields(fields map[string]string) ([]byte, error) {
	if len(fields) > maxControlFields {
		return nil, ErrProxyProtocol
	}
	keys := make([]string, 0, len(fields))
	for key, value := range fields {
		if key == "" || len(key) > 32 || strings.ContainsAny(key, "=\r\n\x00") ||
			!utf8.ValidString(key) || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') || len(value) > maxFieldValueBytes {
			return nil, ErrProxyProtocol
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	for _, key := range keys {
		result.WriteString(key)
		result.WriteByte('=')
		result.WriteString(strings.ReplaceAll(fields[key], "\n", " "))
		result.WriteByte('\n')
	}
	if result.Len() > maxControlBodyBytes {
		return nil, ErrProxyProtocol
	}
	return []byte(result.String()), nil
}

func decodeFields(data []byte) (map[string]string, error) {
	if len(data) > maxControlBodyBytes || !utf8.Valid(data) || strings.ContainsRune(string(data), '\x00') {
		return nil, ErrProxyProtocol
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if strings.ContainsRune(line, '\r') {
			return nil, ErrProxyProtocol
		}
		key, value, exists := strings.Cut(line, "=")
		if !exists || key == "" || len(key) > 32 || strings.ContainsRune(key, '\r') || len(value) > maxFieldValueBytes {
			return nil, ErrProxyProtocol
		}
		if _, duplicate := fields[key]; duplicate || len(fields) >= maxControlFields {
			return nil, ErrProxyProtocol
		}
		fields[key] = value
	}
	return fields, nil
}

func newStream(key, nonce [16]byte) cipher.Stream {
	block, _ := aes.NewCipher(key[:]) // Both arguments have the fixed AES-128 size.
	return cipher.NewCTR(block, nonce[:])
}

func encryptBody(key, nonce [16]byte, body []byte) []byte {
	result := make([]byte, len(body))
	newStream(key, nonce).XORKeyStream(result, body)
	return result
}

func readOuterReply(reader io.Reader, key [16]byte) error {
	payload, err := DecodeControlResponse(reader, key, maxOuterReplyBytes)
	if err != nil {
		return errors.Join(ErrProxyProtocol, err)
	}
	fields, err := decodeFields(payload)
	if err != nil || fields["code"] != "200" {
		return ErrProxyProtocol
	}
	return nil
}

// The encrypted target request is SOCKS5 CONNECT, built at 0x10006ed03..
// 0x10006ef83. Only IPv4 and domain targets were established in that path.
func connectRequest(network, address string) ([]byte, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("proxy supports TCP IPv4 and domain targets only")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\x00") || !utf8.ValidString(host) {
		return nil, errors.New("invalid proxy target address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid proxy target port")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		ip = ip.To4()
		if ip == nil {
			return nil, errors.New("IPv6 proxy targets are unsupported")
		}
		request = append(request, 1)
		request = append(request, ip...)
	} else {
		if strings.ContainsRune(host, ':') || len(host) > 255 {
			return nil, errors.New("invalid proxy target domain")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	return binary.BigEndian.AppendUint16(request, uint16(port)), nil
}

func readConnectReply(reader io.Reader, stream cipher.Stream) error {
	reader = &cipher.StreamReader{S: stream, R: reader}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return errors.Join(ErrProxyProtocol, err)
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return ErrProxyProtocol
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = net.IPv4len
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return errors.Join(ErrProxyProtocol, err)
		}
		addressLength = int(length[0])
		if addressLength == 0 {
			return ErrProxyProtocol
		}
	default:
		return ErrProxyProtocol
	}
	_, err := io.CopyN(io.Discard, reader, int64(addressLength+2))
	if err != nil {
		return errors.Join(ErrProxyProtocol, err)
	}
	return nil
}
