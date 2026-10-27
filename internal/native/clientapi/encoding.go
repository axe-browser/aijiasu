// Package clientapi provides offline encoding primitives observed in the Linux
// amd64 client 4.3.0.1. Form serialization was traced at 0x43f196–0x43f354;
// signature construction and hashing at 0x4436e5–0x443a6e and
// 0x4435c5–0x4436e5. These primitives have not been validated against a live service.
package clientapi

import (
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

const (
	lowercaseHex      = "0123456789abcdef"
	signatureInitialA = uint32(0xdeadbeef)
	signatureInitialB = uint32(0xcafebabe)
)

// EncodeForm sorts keys by their bytes and percent-encodes value bytes with
// lowercase hex digits. Keys remain unescaped, matching the observed serializer.
// Rejecting empty keys and field separators is this module's input protection;
// it is not a validation rule established for the original client.
func EncodeForm(fields map[string]string) (string, error) {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var body strings.Builder
	for index, key := range keys {
		if key == "" || strings.ContainsAny(key, "&=\r\n") {
			return "", errors.New("form keys must be nonempty and contain no &, =, CR, or LF")
		}
		if index > 0 {
			body.WriteByte('&')
		}
		body.WriteString(key)
		body.WriteByte('=')
		value := fields[key]
		for i := 0; i < len(value); i++ {
			c := value[i]
			if isUnreserved(c) {
				body.WriteByte(c)
				continue
			}
			body.WriteByte('%')
			body.WriteByte(lowercaseHex[c>>4])
			body.WriteByte(lowercaseHex[c&0x0f])
		}
	}
	return body.String(), nil
}

func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// RequestSignature hashes the exact body bytes and the caller-supplied seed and
// timestamp using the observed 4.3.0.1 algorithm. The native clock path uses
// monotonic milliseconds; clock/server compatibility remains unverified. The
// caller must supply the appropriate seed; this function chooses neither a clock
// nor a seed.
func RequestSignature(seed, exactBody string, timestampMilliseconds uint64) string {
	a, b := signatureInitialA, signatureInitialB
	parts := []string{seed, "|", exactBody, "|", strconv.FormatUint(timestampMilliseconds, 10), "|", seed}
	for _, part := range parts {
		for i := 0; i < len(part); i++ {
			c := uint32(part[i])
			a ^= (a << 5) + c + (a >> 2)
			b = c + (b << 6) + (b << 16) - b
		}
	}

	var digest [8]byte
	for i := 0; i < 4; i++ {
		shift := uint(24 - i*8)
		digest[i*2] = byte(a >> shift)
		digest[i*2+1] = byte(b >> shift)
	}
	return hex.EncodeToString(digest[:])
}
