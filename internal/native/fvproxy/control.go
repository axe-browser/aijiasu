// Package fvproxy implements the observed FVProxy v2 control-frame encoding.
// The layout was recovered from vpnclientsvc 4.9.6.0 (x86_64), at request writer
// 0x100085910 and response reader 0x1000862d0. Basic service interoperability was
// verified against live nodes on 2026-10-26; this is not full protocol coverage.
// Engine implements the separately recovered TCP authentication and proxy path.
// The outer frame transmits its AES key in clear and provides compatibility
// obfuscation only.
package fvproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	controlHeaderSize = 4
	controlKeySize    = aes.BlockSize

	// MaxControlPayload is the largest payload representable by the v2 header.
	MaxControlPayload = 1<<16 - 1
)

// EncodeControlRequest encodes an opaque control payload with the supplied
// per-request key. The caller supplies any already-encrypted authentication body;
// it is appended unchanged and is not included in the control payload length.
// Payload fields, padding, key generation, and body encryption belong to callers.
func EncodeControlRequest(key [controlKeySize]byte, payload, body []byte) ([]byte, error) {
	if len(payload) > MaxControlPayload {
		return nil, fmt.Errorf("control payload length %d exceeds maximum %d", len(payload), MaxControlPayload)
	}
	controlSize := controlKeySize + controlHeaderSize + len(payload)
	maxInt := int(^uint(0) >> 1)
	if len(body) > maxInt-controlSize {
		return nil, fmt.Errorf("control request body is too large")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create control request cipher: %w", err)
	}
	frame := make([]byte, controlSize+len(body))
	copy(frame[:controlKeySize], key[:])
	header := frame[controlKeySize : controlKeySize+controlHeaderSize]
	binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))
	copy(frame[controlKeySize+controlHeaderSize:controlSize], payload)
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	stream.XORKeyStream(frame[controlKeySize:controlSize], frame[controlKeySize:controlSize])
	copy(frame[controlSize:], body)
	return frame, nil
}

// DecodeControlResponse reads one v2 control response using its request's key.
// Responses omit the request's cleartext key prefix. maxPayload must be between
// 1 and MaxControlPayload; a frame larger than that bound is rejected before its
// payload is read or allocated. Bytes after the frame remain in r.
// A decoded payload is not an authenticated or interpreted server response.
func DecodeControlResponse(r io.Reader, key [controlKeySize]byte, maxPayload int) ([]byte, error) {
	if maxPayload < 1 || maxPayload > MaxControlPayload {
		return nil, fmt.Errorf("control response payload limit must be between 1 and %d", MaxControlPayload)
	}
	if r == nil {
		return nil, fmt.Errorf("control response reader is required")
	}

	header := make([]byte, controlHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read control response header: %w", err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create control response cipher: %w", err)
	}
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	stream.XORKeyStream(header, header)
	if header[0] != 0 || header[1] != 0 {
		return nil, fmt.Errorf("invalid control response header marker")
	}
	payloadSize := int(binary.BigEndian.Uint16(header[2:]))
	if payloadSize > maxPayload {
		return nil, fmt.Errorf("control response payload length %d exceeds limit %d", payloadSize, maxPayload)
	}
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read control response payload: %w", err)
	}
	stream.XORKeyStream(payload, payload)
	return payload, nil
}
