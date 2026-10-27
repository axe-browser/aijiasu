package clientapi

import "testing"

// These are public, constructed offline vectors, not captured service traffic.
// Form expectations were generated independently with Python urllib.parse.quote
// and lowercase percent escapes. Signature expectations used Python big integers
// with explicit 32-bit masks, multiplication by 32/65599, and big-endian bytes.
func TestEncodeFormVectors(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]string
		want   string
	}{
		{name: "nil"},
		{name: "empty", fields: map[string]string{}},
		{
			name:   "sorted keys and delimiters",
			fields: map[string]string{"b": "two words", "a": "&=+"},
			want:   "a=%26%3d%2b&b=two%20words",
		},
		{
			name: "unicode and raw key byte order",
			fields: map[string]string{
				"z":    "空 格&=+/%",
				"A":    "AZaz09-._~",
				"a":    "é🙂",
				"_key": "",
				"中":    "换行\r\n",
			},
			want: "A=AZaz09-._~&_key=&a=%c3%a9%f0%9f%99%82&z=%e7%a9%ba%20%e6%a0%bc%26%3d%2b%2f%25&中=%e6%8d%a2%e8%a1%8c%0d%0a",
		},
		{
			name: "public account placeholders",
			fields: map[string]string{
				"cmd":      "ClientApiLogin/Login",
				"username": "demo@example.test",
				"password": "公開的测试值 +&=",
			},
			want: "cmd=ClientApiLogin%2fLogin&password=%e5%85%ac%e9%96%8b%e7%9a%84%e6%b5%8b%e8%af%95%e5%80%bc%20%2b%26%3d&username=demo%40example.test",
		},
		{
			name:   "value bytes are not normalized",
			fields: map[string]string{"bytes": "\x00\xff"},
			want:   "bytes=%00%ff",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeForm(test.fields)
			if err != nil {
				t.Fatalf("EncodeForm() error: %v", err)
			}
			if got != test.want {
				t.Fatalf("EncodeForm() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEncodeFormRejectsAmbiguousKeys(t *testing.T) {
	for _, key := range []string{"", "a&b", "a=b", "a\rb", "a\nb"} {
		t.Run(key, func(t *testing.T) {
			got, err := EncodeForm(map[string]string{key: "public value"})
			if err == nil {
				t.Fatal("EncodeForm() accepted an invalid key")
			}
			if got != "" {
				t.Fatalf("EncodeForm() returned partial body %q on error", got)
			}
		})
	}
}

func TestRequestSignatureVectors(t *testing.T) {
	tests := []struct {
		name      string
		seed      string
		body      string
		timestamp uint64
		want      string
	}{
		{
			name: "empty input and zero timestamp",
			want: "4bf9fdff9ee8be0a",
		},
		{
			name:      "public baseline",
			seed:      "public-seed",
			body:      "a=1&z=two%20words",
			timestamp: 123456789,
			want:      "e64d7af0efa05c2b",
		},
		{
			name:      "trailing ampersand changes exact bytes",
			seed:      "public-seed",
			body:      "a=1&z=two%20words&",
			timestamp: 123456789,
			want:      "8707b14e8bb2e0df",
		},
		{
			name:      "different public seed",
			seed:      "different-public-seed",
			body:      "a=1&z=two%20words",
			timestamp: 123456789,
			want:      "e9f2ec9b70ff7583",
		},
		{
			name:      "different timestamp",
			seed:      "public-seed",
			body:      "a=1&z=two%20words",
			timestamp: 123456790,
			want:      "b18fdba74bbe3b61",
		},
		{
			name: "unicode bytes and zero timestamp",
			seed: "公开种子",
			body: "姓名=%e7%94%b2%20%e4%b9%99&x=%26%3d",
			want: "ad5eaaba7dbe2888",
		},
		{
			name:      "maximum uint64 timestamp",
			timestamp: ^uint64(0),
			want:      "0cb8caaf8fc2b099",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := RequestSignature(test.seed, test.body, test.timestamp)
			if got != test.want {
				t.Fatalf("RequestSignature() = %q, want %q", got, test.want)
			}
		})
	}
}
