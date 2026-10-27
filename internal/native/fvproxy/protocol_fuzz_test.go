package fvproxy

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzControlAndConnectResponses(f *testing.F) {
	var key [16]byte
	for _, payload := range [][]byte{nil, []byte("code=200\n"), []byte("code=403\n"), []byte("code=200\ncode=200\n")} {
		frame, err := EncodeControlRequest(key, payload, nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frame[controlKeySize:])
	}
	for _, packet := range [][]byte{{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}, {5, 0, 0, 3, 1, 'a', 0, 80}, {5, 0, 0, 3, 0}} {
		f.Add(encryptBody(key, key, packet))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		const maximum = 4096
		payload, err := DecodeControlResponse(bytes.NewReader(data), key, maximum)
		if err == nil && len(payload) > maximum {
			t.Fatal("untrusted frame bypassed its allocation bound")
		}
		// Both reply parsers receive arbitrary network bytes. Their fixed headers
		// and bounded address lengths must never panic or read without a bound.
		_ = readConnectReply(bytes.NewReader(data), newStream(key, key))
	})
}

func FuzzControlFieldNormalization(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("c=pong\n"), []byte("code=200\r\n"), []byte("sid=public-test\nka=5\n"), []byte("c=pong\nc=pong\n"), {0xff, 0, '\n'}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fields, err := decodeFields(data)
		if err != nil {
			return
		}
		if len(fields) > maxControlFields {
			t.Fatal("decoded field count exceeds its resource bound")
		}
		canonical, err := encodeFields(fields)
		if err != nil {
			// An unterminated maximum-size input can need one additional LF when
			// canonicalized, so the encoder may correctly reject its size.
			return
		}
		roundTrip, err := decodeFields(canonical)
		if err != nil || !reflect.DeepEqual(fields, roundTrip) {
			t.Fatal("accepted control fields did not survive canonical framing")
		}
	})
}
