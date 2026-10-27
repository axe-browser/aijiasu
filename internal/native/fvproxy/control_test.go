package fvproxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// These are constructed vectors, not captured service traffic. Their ciphertext
// was generated independently with Node.js crypto.createCipheriv("aes-128-ctr",
// key, Buffer.alloc(16)), over Buffer.concat([header, payload]), where header is
// four zero bytes with payload.length written as uint16be at offset two.
const (
	vectorKeyHex          = "000102030405060708090a0b0c0d0e0f"
	vectorPayload         = "s=site\nn=nonce\nk=key\nl=4\n_=\n"
	vectorRequestHex      = "000102030405060708090a0b0c0d0e0fc6a13b2bf4b228eb1b2a8b0c9ca6b717102319fea8abd167431780d76fab1000deadbeef"
	vectorResponseHex     = "c6a13b3ee4e03fe7527db152ab"
	vectorEmptyRequestHex = "000102030405060708090a0b0c0d0e0fc6a13b37"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return decoded
}

func vectorKey(t *testing.T) [controlKeySize]byte {
	t.Helper()
	var key [controlKeySize]byte
	copy(key[:], decodeHex(t, vectorKeyHex))
	return key
}

func TestEncodeControlRequestVector(t *testing.T) {
	payload := []byte(vectorPayload)
	body := decodeHex(t, "deadbeef")
	payloadBefore := bytes.Clone(payload)
	bodyBefore := bytes.Clone(body)
	frame, err := EncodeControlRequest(vectorKey(t), payload, body)
	if err != nil {
		t.Fatalf("encode control request: %v", err)
	}
	if got := hex.EncodeToString(frame); got != vectorRequestHex {
		t.Fatalf("request = %s, want %s", got, vectorRequestHex)
	}
	if !bytes.Equal(payload, payloadBefore) || !bytes.Equal(body, bodyBefore) {
		t.Fatal("encoding modified caller data")
	}
}

func TestEncodeControlRequestEmptyVector(t *testing.T) {
	frame, err := EncodeControlRequest(vectorKey(t), nil, nil)
	if err != nil {
		t.Fatalf("encode empty request: %v", err)
	}
	if got := hex.EncodeToString(frame); got != vectorEmptyRequestHex {
		t.Fatalf("empty request = %s, want %s", got, vectorEmptyRequestHex)
	}
}

func TestEncodeControlRequestPayloadBound(t *testing.T) {
	key := vectorKey(t)
	frame, err := EncodeControlRequest(key, make([]byte, MaxControlPayload), nil)
	if err != nil {
		t.Fatalf("maximum payload rejected: %v", err)
	}
	if got, want := len(frame), controlKeySize+controlHeaderSize+MaxControlPayload; got != want {
		t.Fatalf("maximum frame length = %d, want %d", got, want)
	}
	if _, err := EncodeControlRequest(key, make([]byte, MaxControlPayload+1), nil); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestDecodeControlResponseVector(t *testing.T) {
	for _, shortReads := range []bool{false, true} {
		t.Run(fmt.Sprintf("short_reads_%t", shortReads), func(t *testing.T) {
			var reader io.Reader = bytes.NewReader(decodeHex(t, vectorResponseHex))
			if shortReads {
				reader = iotest.OneByteReader(reader)
			}
			payload, err := DecodeControlResponse(reader, vectorKey(t), MaxControlPayload)
			if err != nil {
				t.Fatalf("decode control response: %v", err)
			}
			if got, want := string(payload), "code=200\n"; got != want {
				t.Fatalf("payload = %q, want %q", got, want)
			}
		})
	}
}

func TestDecodeControlResponseTruncated(t *testing.T) {
	frame := decodeHex(t, vectorResponseHex)
	key := vectorKey(t)
	for n := 0; n < len(frame); n++ {
		t.Run(fmt.Sprintf("bytes_%d", n), func(t *testing.T) {
			_, err := DecodeControlResponse(bytes.NewReader(frame[:n]), key, MaxControlPayload)
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated response error = %v, want EOF or unexpected EOF", err)
			}
		})
	}
}

func TestDecodeControlResponseInvalidMarker(t *testing.T) {
	frame := decodeHex(t, vectorResponseHex)
	frame[0] ^= 1
	reader := bytes.NewReader(frame)
	if _, err := DecodeControlResponse(reader, vectorKey(t), MaxControlPayload); err == nil || !strings.Contains(err.Error(), "header marker") {
		t.Fatalf("invalid marker error = %v", err)
	}
	if got, want := reader.Len(), len(frame)-controlHeaderSize; got != want {
		t.Fatalf("unread bytes = %d, want %d", got, want)
	}
}

func TestDecodeControlResponsePayloadLimit(t *testing.T) {
	frame := decodeHex(t, vectorResponseHex)
	reader := bytes.NewReader(frame)
	if _, err := DecodeControlResponse(reader, vectorKey(t), len("code=200\n")-1); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("payload limit error = %v", err)
	}
	if got, want := reader.Len(), len(frame)-controlHeaderSize; got != want {
		t.Fatalf("unread bytes = %d, want %d", got, want)
	}
}

func TestDecodeControlResponseInvalidLimit(t *testing.T) {
	frame := decodeHex(t, vectorResponseHex)
	key := vectorKey(t)
	for _, maxPayload := range []int{-1, 0, MaxControlPayload + 1} {
		t.Run(fmt.Sprintf("limit_%d", maxPayload), func(t *testing.T) {
			reader := bytes.NewReader(frame)
			if _, err := DecodeControlResponse(reader, key, maxPayload); err == nil {
				t.Fatal("invalid payload limit accepted")
			}
			if got := reader.Len(); got != len(frame) {
				t.Fatalf("invalid limit consumed input: %d bytes remain", got)
			}
		})
	}
}

func TestDecodeControlResponsePreservesTrailingBytes(t *testing.T) {
	trailer := []byte{0x11, 0x22, 0x33}
	reader := bytes.NewReader(append(decodeHex(t, vectorResponseHex), trailer...))
	if _, err := DecodeControlResponse(reader, vectorKey(t), MaxControlPayload); err != nil {
		t.Fatalf("decode frame with trailer: %v", err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read trailer: %v", err)
	}
	if !bytes.Equal(remaining, trailer) {
		t.Fatalf("remaining bytes = %x, want %x", remaining, trailer)
	}
}

func TestDecodeControlResponseRequiresReader(t *testing.T) {
	if _, err := DecodeControlResponse(nil, vectorKey(t), MaxControlPayload); err == nil {
		t.Fatal("nil reader accepted")
	}
}

func TestDecodeControlResponsePreservesReaderError(t *testing.T) {
	want := errors.New("reader failed")
	if _, err := DecodeControlResponse(iotest.ErrReader(want), vectorKey(t), MaxControlPayload); !errors.Is(err, want) {
		t.Fatalf("reader error = %v, want wrapped original error", err)
	}
}
