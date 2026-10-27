//go:build darwin || linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
)

const terminalPTYHelperEnv = "AIJIASU_NATIVE_PUBLIC_PTY_TEST_HELPER"
const terminalPTYCaseEnv = "AIJIASU_NATIVE_PUBLIC_PTY_TEST_CASE"

func TestTerminalPTYHelper(t *testing.T) {
	if os.Getenv(terminalPTYHelperEnv) != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	expected := "  public-fixture  "
	fixture := os.Getenv(terminalPTYCaseEnv)
	if strings.HasPrefix(fixture, "length-") {
		length, err := strconv.Atoi(strings.TrimPrefix(fixture, "length-"))
		if err != nil || length < 1 || length > maxPasswordBytes+1 {
			t.Fatal("invalid public PTY length fixture")
		}
		expected = strings.Repeat("x", length)
	} else {
		switch fixture {
		case "unicode-edit":
			expected = "ab密!"
		case "clear-line":
			expected = "kept"
		case "partial-eof":
			expected = "eof-fixture"
		case "chunked":
			expected = "chunked-password"
		}
	}
	dependencies := testDependencies()
	dependencies.readPassword = func(ctx context.Context) ([]byte, error) {
		password, err := readTerminalPassword(ctx)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "public-fixture terminal error: %v\n", err)
		}
		return password, err
	}
	loginCalls, saveCalls := 0, 0
	dependencies.newClient = func(clientapi.Config) (loginClient, error) {
		return fakeLoginClient(func(_ context.Context, username string, password []byte) (clientapi.Session, error) {
			loginCalls++
			if username != "public-fixture" || string(password) != expected {
				return clientapi.Session{}, fmt.Errorf("public PTY fixture mismatch")
			}
			return clientapi.Session{Username: username, LoginToken: "public-test-token"}, nil
		}), nil
	}
	dependencies.saveLoginSession = func(context.Context, string, authstore.LoginVersion, clientapi.Session) error {
		saveCalls++
		return nil
	}
	code := run(ctx, []string{"login", "-u", "public-fixture"}, os.Stdin, os.Stdout, os.Stderr, dependencies)
	stop()
	fmt.Printf("\nPTY_RESULT:%d:%d:%d\n", code, loginCalls, saveCalls)
	// Keep the controlling session alive while the driver verifies restoration.
	time.Sleep(500 * time.Millisecond)
	os.Exit(code)
}

func TestTerminalRealPTYSignalsAndEchoRestoration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required to drive the operating system PTY")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"SIGINT", "SIGTERM", "typed-interrupt", "password", "length-128", "length-1023", "length-1024", "length-2048", "length-4096", "length-4097", "oversize-tail", "oversize-cancel", "unicode-edit", "clear-line", "partial-eof", "empty-eof", "empty-line", "chunked"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, python, "-c", terminalPTYDriver, executable, action)
			command.Env = append(os.Environ(), terminalPTYHelperEnv+"=1", terminalPTYCaseEnv+"="+action)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("public-fixture PTY driver failed: %v\n%s", err, output)
			}
			var result struct {
				ExitCode int    `json:"exit_code"`
				Restored bool   `json:"restored"`
				Leaked   bool   `json:"leaked"`
				Sent     int    `json:"sent"`
				Expected int    `json:"expected_sent"`
				Hidden   bool   `json:"hidden_until_line_end"`
				Output   string `json:"public_fixture_output"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode PTY driver result: %v\n%s", err, output)
			}
			want := 0
			switch action {
			case "SIGINT", "SIGTERM", "typed-interrupt", "oversize-cancel":
				want = exitCancelled
			case "length-4097", "oversize-tail", "empty-eof", "empty-line":
				want = exitFailure
			}
			if result.ExitCode != want || !result.Restored || result.Leaked || result.Sent != result.Expected || !result.Hidden {
				t.Fatalf("PTY %s failed: %+v", action, result)
			}
		})
	}
}

const terminalPTYDriver = `
import fcntl, json, os, pty, re, select, signal, subprocess, sys, termios, time

master, slave = pty.openpty()
original = termios.tcgetattr(slave)
def setup():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.tcsetpgrp(slave, os.getpgrp())

process = subprocess.Popen([sys.argv[1], '-test.run=^TestTerminalPTYHelper$'],
    stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    pass_fds=(slave,), preexec_fn=setup)
output = bytearray()
os.set_blocking(master, False)
def read_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        readable, _, _ = select.select([master], [], [], 0.05)
        if readable:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        if process.poll() is not None:
            break
    raise RuntimeError('PTY child failed to reach expected state: ' + output.decode('utf8', 'replace'))

def write_all(data):
    sent = 0
    deadline = time.monotonic() + 5
    while sent < len(data):
        if time.monotonic() > deadline:
            raise RuntimeError('PTY could not send the complete public fixture')
        _, writable, _ = select.select([], [master], [], 0.05)
        if not writable:
            continue
        try:
            written = os.write(master, data[sent:sent + 128])
        except BlockingIOError:
            continue
        if written <= 0:
            raise RuntimeError('PTY accepted no public fixture bytes')
        sent += written
        time.sleep(0.002)
    return sent

try:
    read_until(lambda: '密码:'.encode() in output and not (termios.tcgetattr(slave)[3] & termios.ECHO))
    action = sys.argv[2]
    if action.startswith('length-'):
        payload = b'x' * int(action.split('-')[1]) + b'\n'
    elif action == 'unicode-edit':
        payload = 'ab密码'.encode() + b'\x7f' + '文'.encode() + b'\b!\r\n'
    elif action == 'clear-line':
        payload = b'discarded\x15kept\n'
    elif action == 'partial-eof':
        payload = b'eof-fixture\x04'
    elif action == 'empty-eof':
        payload = b'\x04'
    elif action == 'empty-line':
        payload = b'\n'
    elif action == 'chunked':
        payload = b'chunked-password\n'
    elif action == 'typed-interrupt':
        payload = b'public-fixture-partial\x03'
    elif action == 'password':
        payload = b'  public-fixture  \n'
    else:
        payload = b'public-fixture-partial'
    hidden_until_line_end = True
    if action in ('oversize-tail', 'oversize-cancel'):
        payload = b'x' * 4097
        sent = write_all(payload)
        time.sleep(0.15)
        hidden_until_line_end = not (termios.tcgetattr(slave)[3] & termios.ECHO)
        if action == 'oversize-tail':
            tail = b'public-delayed-tail' + b'\b\x15' + b'more-private-tail\n'
            payload += tail
            for offset in range(0, len(tail), 5):
                sent += write_all(tail[offset:offset + 5])
                time.sleep(0.02)
                if offset + 5 < len(tail):
                    hidden_until_line_end = hidden_until_line_end and not (termios.tcgetattr(slave)[3] & termios.ECHO)
        else:
            os.kill(process.pid, signal.SIGINT)
    elif action == 'chunked':
        sent = sum(write_all(bytes([value])) for value in payload)
    else:
        sent = write_all(payload)
    if action in ('SIGINT', 'SIGTERM'):
        os.kill(process.pid, getattr(signal, action))
    read_until(lambda: b'PTY_RESULT:' in output)
    after = termios.tcgetattr(slave)
    restored = after == original
    marker = re.search(rb'PTY_RESULT:(\d+):(\d+):(\d+)', output)
    if marker is None:
        raise RuntimeError('missing helper result')
    expected_calls = 0 if action in ('SIGINT', 'SIGTERM', 'typed-interrupt', 'length-4097', 'oversize-tail', 'oversize-cancel', 'empty-eof', 'empty-line') else 1
    if int(marker[2]) != expected_calls or int(marker[3]) != expected_calls:
        raise RuntimeError('unexpected authentication or storage call count')
    leaked = any(value in output for value in (b'public-fixture-partial', b'  public-fixture  ', b'x' * 64, b'discarded', b'eof-fixture', b'chunked-password', b'public-delayed-tail', b'more-private-tail', 'ab密'.encode()))
    exit_code = process.wait(timeout=5)
    print(json.dumps({'exit_code': exit_code, 'restored': restored, 'leaked': leaked, 'sent': sent, 'expected_sent': len(payload), 'hidden_until_line_end': hidden_until_line_end, 'public_fixture_output': output.decode('utf8', 'replace')}))
finally:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    try:
        termios.tcsetattr(slave, termios.TCSANOW, original)
    except termios.error:
        pass
    os.close(master)
    os.close(slave)
`
