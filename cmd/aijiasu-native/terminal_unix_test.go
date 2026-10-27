//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeTerminalFile struct {
	closed bool
}

func (terminal *fakeTerminalFile) Fd() uintptr { return 42 }
func (terminal *fakeTerminalFile) Close() error {
	terminal.closed = true
	return nil
}

func terminalTestOperations(terminal *fakeTerminalFile, read func(int, []byte) (int, error), restore func(int, *unix.Termios) error) terminalOperations {
	original := &unix.Termios{
		Lflag: unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN,
		Iflag: unix.IXON | unix.IXOFF | unix.INLCR | unix.IGNCR | unix.ISTRIP,
	}
	original.Cc[unix.VERASE], original.Cc[unix.VKILL], original.Cc[unix.VEOF] = '\x7f', '\x15', '\x04'
	return terminalOperations{
		open:     func() (terminalFile, error) { return terminal, nil },
		getState: func(int) (*unix.Termios, error) { return original, nil },
		setState: func(fd int, state *unix.Termios) error {
			if state == original {
				return restore(fd, state)
			}
			if state.Lflag&(unix.ECHO|unix.ECHONL|unix.ICANON|unix.IEXTEN) != 0 || state.Lflag&unix.ISIG == 0 || state.Iflag&(unix.IXON|unix.IXOFF) != 0 || state.Cc[unix.VMIN] != 1 || state.Cc[unix.VTIME] != 0 {
				return errors.New("invalid hidden terminal mode")
			}
			return nil
		},
		flushInput:   func(int) error { return nil },
		waitReadable: func(context.Context, int) error { return nil },
		read:         read,
	}
}

func TestTerminalIncrementalInputEditsAndBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		chunks  []string
		want    string
		wantErr error
	}{
		{"split-line", []string{"  pass", "word  ", "\n"}, "  password  ", nil},
		{"CRLF", []string{"password\r\n"}, "password", nil},
		{"unicode-erase", []string{"ab密", "码\x7f", "文\b", "!\n"}, "ab密!", nil},
		{"clear-line", []string{"discarded", "\x15", "kept\n"}, "kept", nil},
		{"empty-erase", []string{"\b\x7fpassword\n"}, "password", nil},
		{"partial-EOF", []string{"password\x04"}, "password", nil},
		{"empty-EOF", []string{"\x04"}, "", io.EOF},
		{"empty-line", []string{"\n"}, "", errPasswordEmpty},
		{"maximum", []string{strings.Repeat("x", maxPasswordBytes) + "\n"}, strings.Repeat("x", maxPasswordBytes), nil},
		{"oversize", []string{strings.Repeat("x", maxPasswordBytes+1) + "\n"}, "", errPasswordTooLong},
		{"oversize-stays-rejected-after-edit", []string{strings.Repeat("x", maxPasswordBytes+1), "\b\x15new\n"}, "", errPasswordTooLong},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminal := &fakeTerminalFile{}
			remaining := append([]string(nil), test.chunks...)
			operations := terminalTestOperations(terminal, func(_ int, buffer []byte) (int, error) {
				if len(remaining) == 0 {
					return 0, nil
				}
				n := copy(buffer, remaining[0])
				remaining[0] = remaining[0][n:]
				if remaining[0] == "" {
					remaining = remaining[1:]
				}
				return n, nil
			}, func(int, *unix.Termios) error { return nil })
			password, err := readTerminalPasswordWith(context.Background(), operations)
			if !errors.Is(err, test.wantErr) || string(password) != test.want || !terminal.closed {
				t.Fatal("incremental password input changed its content, error, or cleanup")
			}
		})
	}
}

func TestOversizeTerminalInputCanStillBeCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	terminal := &fakeTerminalFile{}
	input := strings.NewReader(strings.Repeat("x", maxPasswordBytes+1))
	restored := false
	operations := terminalTestOperations(terminal, func(_ int, buffer []byte) (int, error) {
		return input.Read(buffer)
	}, func(int, *unix.Termios) error { restored = true; return nil })
	operations.waitReadable = func(context.Context, int) error {
		if input.Len() == 0 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	password, err := readTerminalPasswordWith(ctx, operations)
	if password != nil || !errors.Is(err, context.Canceled) || !restored || !terminal.closed {
		t.Fatal("cancellation did not interrupt rejected-line draining and restore the terminal")
	}
}

func TestTerminalCancellationRestoresWithoutStartingRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	terminal := &fakeTerminalFile{}
	started := make(chan struct{})
	restored, flushed := false, false
	reads := 0
	operations := terminalTestOperations(terminal, func(int, []byte) (int, error) {
		reads++
		return 0, nil
	}, func(int, *unix.Termios) error {
		if terminal.closed || !flushed {
			return errors.New("terminal restored after close or before flushing input")
		}
		restored = true
		return nil
	})
	operations.flushInput = func(int) error { flushed = true; return nil }
	operations.waitReadable = func(ctx context.Context, _ int) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	finished := make(chan error, 1)
	go func() {
		_, err := readTerminalPasswordWith(ctx, operations)
		finished <- err
	}()
	<-started
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || !restored || !terminal.closed || reads != 0 {
			t.Fatal("cancelled password input did not restore and close without a blocked read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal cancellation did not finish")
	}
}

func TestTerminalRestoreFailureDiscardsPassword(t *testing.T) {
	terminal := &fakeTerminalFile{}
	var captured []byte
	operations := terminalTestOperations(terminal, func(_ int, buffer []byte) (int, error) {
		n := copy(buffer, "synthetic-password\n")
		captured = buffer[:n]
		return n, nil
	}, func(int, *unix.Termios) error { return errors.New("restore failed") })
	password, err := readTerminalPasswordWith(context.Background(), operations)
	if password != nil || !errors.Is(err, errTerminalRestore) || !terminal.closed || !bytes.Equal(captured[:len(captured)-1], make([]byte, len(captured)-1)) {
		t.Fatal("terminal restoration failure did not discard the password")
	}
}

func TestTerminalNonblockingReadRetriesWithoutLosingPassword(t *testing.T) {
	terminal := &fakeTerminalFile{}
	reads := 0
	operations := terminalTestOperations(terminal, func(_ int, buffer []byte) (int, error) {
		reads++
		if reads == 1 {
			return 0, unix.EAGAIN
		}
		return copy(buffer, "  fixture  \n"), nil
	}, func(int, *unix.Termios) error { return nil })
	password, err := readTerminalPasswordWith(context.Background(), operations)
	if err != nil || string(password) != "  fixture  " || reads != 2 || !terminal.closed {
		t.Fatal("nonblocking terminal retry changed password or failed to close")
	}
}
