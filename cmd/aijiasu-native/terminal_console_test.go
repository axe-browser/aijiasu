package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
)

type fakePasswordConsole struct {
	batches                   [][]consolePasswordKey
	read                      func(context.Context) ([]consolePasswordKey, error)
	hidden, flushed, restored bool
	closed                    bool
	flushErr, restoreErr      error
}

func (console *fakePasswordConsole) hideInput() (func() error, error) {
	console.hidden = true
	return func() error {
		console.restored = true
		return console.restoreErr
	}, nil
}

func (console *fakePasswordConsole) readKeys(ctx context.Context) ([]consolePasswordKey, error) {
	if console.read != nil {
		return console.read(ctx)
	}
	if len(console.batches) == 0 {
		return nil, io.EOF
	}
	keys := console.batches[0]
	console.batches = console.batches[1:]
	return keys, nil
}

func (console *fakePasswordConsole) flushInput() error {
	console.flushed = true
	return console.flushErr
}

func (console *fakePasswordConsole) Close() error { console.closed = true; return nil }

func consoleKeys(text string) []consolePasswordKey {
	var keys []consolePasswordKey
	for _, character := range utf16.Encode([]rune(text)) {
		keys = append(keys, consolePasswordKey{character: character, repeats: 1})
	}
	return keys
}

func TestConsolePasswordUnicodeEditsAndBounds(t *testing.T) {
	for _, test := range []struct {
		name, text, want string
		wantErr          error
	}{
		{"whitespace", "  public fixture  \r", "  public fixture  ", nil},
		{"UTF16-pair", "密🔑码\r", "密🔑码", nil},
		{"UTF16-erase", "ab密🔑\b!\r", "ab密!", nil},
		{"clear-line", "discarded\x15kept\r", "kept", nil},
		{"EOF", "fixture\x1a", "fixture", nil},
		{"empty-EOF", "\x1a", "", io.EOF},
		{"empty-line", "\r", "", errPasswordEmpty},
		{"interrupt", "partial\x03", "", context.Canceled},
		{"maximum", strings.Repeat("x", maxPasswordBytes) + "\r", strings.Repeat("x", maxPasswordBytes), nil},
		{"unicode-maximum", strings.Repeat("🔑", maxPasswordBytes/4) + "\r", strings.Repeat("🔑", maxPasswordBytes/4), nil},
		{"unicode-oversize", strings.Repeat("🔑", maxPasswordBytes/4) + "a\r", "", errPasswordTooLong},
		{"oversize-stays-rejected", strings.Repeat("x", maxPasswordBytes+1) + "\b\x15new\r", "", errPasswordTooLong},
	} {
		t.Run(test.name, func(t *testing.T) {
			keys := consoleKeys(test.text)
			console := &fakePasswordConsole{batches: [][]consolePasswordKey{keys}}
			password, err := readConsolePassword(context.Background(), console)
			defer clear(password)
			if string(password) != test.want || !errors.Is(err, test.wantErr) {
				t.Fatal("console input changed password content or error")
			}
			if !console.hidden || !console.flushed || !console.restored || !console.closed {
				t.Fatal("console input did not hide, flush, restore and close")
			}
			for _, key := range keys {
				if key != (consolePasswordKey{}) {
					t.Fatal("console input event copy was retained")
				}
			}
		})
	}
}

func TestConsolePasswordSurrogateSplitAndRepeat(t *testing.T) {
	console := &fakePasswordConsole{batches: [][]consolePasswordKey{
		{{character: 0xd83d, repeats: 1}}, {{character: 0xdd11, repeats: 1}},
		{{character: 'x', repeats: 3}, {character: '\r', repeats: 1}},
	}}
	password, err := readConsolePassword(context.Background(), console)
	defer clear(password)
	if err != nil || string(password) != "🔑xxx" {
		t.Fatal("split surrogate or repeated key lost console input")
	}
}

func TestConsolePasswordCancellationAndFailedRestoration(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		console := &fakePasswordConsole{}
		console.read = func(context.Context) ([]consolePasswordKey, error) {
			cancel()
			return consoleKeys("discarded\r"), nil
		}
		password, err := readConsolePassword(ctx, console)
		if password != nil || !errors.Is(err, context.Canceled) || !console.restored || !console.flushed || !console.closed {
			t.Fatal("canceled console read retained input or failed cleanup")
		}
	})
	for _, failure := range []string{"flush", "restore"} {
		t.Run(failure, func(t *testing.T) {
			console := &fakePasswordConsole{batches: [][]consolePasswordKey{consoleKeys("fixture\r")}}
			cause := errors.New("public console error")
			if failure == "flush" {
				console.flushErr = cause
			} else {
				console.restoreErr = cause
			}
			password, err := readConsolePassword(context.Background(), console)
			if password != nil || !errors.Is(err, errTerminalRestore) || !errors.Is(err, cause) || !console.restored || !console.closed {
				t.Fatal("console cleanup failure exposed a password or discarded its cause")
			}
		})
	}
}
