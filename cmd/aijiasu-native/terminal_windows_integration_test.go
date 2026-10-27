//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	nativeConsoleHelperEnv = "AIJIASU_NATIVE_PUBLIC_CONSOLE_HELPER"
	nativeConsoleCaseEnv   = "AIJIASU_NATIVE_PUBLIC_CONSOLE_CASE"
	nativeConsoleMarker    = "NATIVE_CONSOLE_RESULT:"
	nativeConsoleWait      = 6 * time.Second
	nativeConsoleScreenMax = 128 * 1024
)

var (
	nativeConsoleTestDLL        = windows.NewLazySystemDLL("kernel32.dll")
	nativeConsoleTestWriteInput = nativeConsoleTestDLL.NewProc("WriteConsoleInputW")
	nativeConsoleTestInputCount = nativeConsoleTestDLL.NewProc("GetNumberOfConsoleInputEvents")
	nativeConsoleTestReadScreen = nativeConsoleTestDLL.NewProc("ReadConsoleOutputCharacterW")
)

type nativeConsoleReadResult struct {
	password []byte
	err      error
}

type nativeConsoleScreen struct {
	position windows.Coord
	text     []uint16
}

type nativeConsoleTestResult struct {
	Arch         string `json:"arch"`
	Hidden       bool   `json:"hidden"`
	Restored     bool   `json:"restored"`
	NotEchoed    bool   `json:"not_echoed"`
	InputFlushed bool   `json:"input_flushed"`
	ContentOK    bool   `json:"content_ok"`
	ErrorOK      bool   `json:"error_ok"`
}

func TestTerminalWindowsNativeConsole(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{
		"password", "unicode-edit", "split-surrogate", "maximum", "unicode-maximum",
		"oversize-tail", "context-cancel", "oversize-cancel", "console-ctrl-c", "empty-eof", "flush-tail",
	} {
		t.Run(fixture, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestTerminalWindowsNativeConsoleHelper$")
			command.Env = append(os.Environ(), nativeConsoleHelperEnv+"=1", nativeConsoleCaseEnv+"="+fixture)
			// All keyboard events and control signals stay in this separate hidden
			// console, never the test runner's or user's console input buffer.
			command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("native console public fixture failed: %v\n%s", err, output)
			}
			var result nativeConsoleTestResult
			found := false
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, nativeConsoleMarker) {
					if err := json.Unmarshal([]byte(strings.TrimPrefix(line, nativeConsoleMarker)), &result); err != nil {
						t.Fatal("native console helper result is not valid JSON")
					}
					found = true
				}
			}
			if !found || result.Arch != runtime.GOARCH || !result.Hidden || !result.Restored || !result.NotEchoed || !result.InputFlushed || !result.ContentOK || !result.ErrorOK {
				t.Fatalf("native console fixture did not meet its acceptance conditions: %+v", result)
			}
		})
	}
}

func TestTerminalWindowsNativeConsoleHelper(t *testing.T) {
	if os.Getenv(nativeConsoleHelperEnv) != "1" {
		return
	}
	if unsafe.Sizeof(consoleInputRecord{}) != 20 || unsafe.Offsetof(consoleInputRecord{}.character) != 14 {
		t.Fatal("console input record layout does not match Win32")
	}
	input := nativeConsoleOpen(t, "CONIN$")
	defer windows.CloseHandle(input)
	output := nativeConsoleOpen(t, "CONOUT$")
	defer windows.CloseHandle(output)
	var original uint32
	if err := windows.GetConsoleMode(input, &original); err != nil {
		t.Fatal(err)
	}
	// Exercise restoration of enabled echo, line input and quick-edit flags.
	original |= windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT |
		windows.ENABLE_EXTENDED_FLAGS | windows.ENABLE_QUICK_EDIT_MODE
	if err := windows.SetConsoleMode(input, original); err != nil {
		t.Fatal(err)
	}
	if err := windows.FlushConsoleInputBuffer(input); err != nil {
		t.Fatal(err)
	}
	before := nativeConsoleSnapshot(t, output)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	results := make(chan nativeConsoleReadResult, 1)
	go func() {
		password, err := readTerminalPassword(ctx)
		results <- nativeConsoleReadResult{password, err}
	}()
	nativeConsoleWaitHidden(t, input, results)
	fixture := os.Getenv(nativeConsoleCaseEnv)
	expected := "public-fixture"
	var expectedError error
	switch fixture {
	case "password":
		nativeConsoleWrite(t, input, expected+"\r")
	case "unicode-edit":
		expected = "ab密!"
		nativeConsoleWrite(t, input, "ab密🔑\b!\r")
	case "split-surrogate":
		expected = "🔑!"
		nativeConsoleWriteUnits(t, input, []uint16{0xd83d})
		nativeConsoleWaitDrained(t, input)
		nativeConsoleAssertPendingHidden(t, input, results)
		nativeConsoleWriteUnits(t, input, []uint16{0xdd11, '!', '\r'})
	case "maximum", "unicode-maximum":
		expected = strings.Repeat("x", maxPasswordBytes)
		if fixture == "unicode-maximum" {
			expected = strings.Repeat("🔑", maxPasswordBytes/4)
		}
		nativeConsoleWrite(t, input, expected)
		nativeConsoleWaitDrained(t, input)
		nativeConsoleAssertPendingHidden(t, input, results)
		nativeConsoleWrite(t, input, "\r")
	case "oversize-tail", "oversize-cancel":
		expected = ""
		expectedError = errPasswordTooLong
		nativeConsoleWrite(t, input, strings.Repeat("x", maxPasswordBytes+1))
		nativeConsoleWaitDrained(t, input)
		nativeConsoleAssertPendingHidden(t, input, results)
		nativeConsoleWrite(t, input, "\b\x15slow-tail")
		nativeConsoleWaitDrained(t, input)
		nativeConsoleAssertPendingHidden(t, input, results)
		if fixture == "oversize-cancel" {
			expectedError = context.Canceled
			cancel()
		} else {
			nativeConsoleWrite(t, input, "\r")
		}
	case "context-cancel", "console-ctrl-c":
		expected = ""
		expectedError = context.Canceled
		nativeConsoleWrite(t, input, "unfinished-public-fixture")
		nativeConsoleWaitDrained(t, input)
		nativeConsoleAssertPendingHidden(t, input, results)
		if fixture == "console-ctrl-c" {
			if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0); err != nil {
				t.Fatal("cannot generate an interrupt in the helper's isolated console")
			}
		} else {
			cancel()
		}
	case "empty-eof":
		expected = ""
		expectedError = io.EOF
		nativeConsoleWrite(t, input, "\x1a")
	case "flush-tail":
		expected = "public"
		nativeConsoleWrite(t, input, expected+"\rdiscard-this-tail")
	default:
		t.Fatal("unknown public console fixture")
	}
	var actual nativeConsoleReadResult
	select {
	case actual = <-results:
	case <-time.After(nativeConsoleWait):
		t.Fatal("native console password read did not finish")
	}
	defer clear(actual.password)
	var restored uint32
	if err := windows.GetConsoleMode(input, &restored); err != nil {
		t.Fatal(err)
	}
	after := nativeConsoleSnapshot(t, output)
	result := nativeConsoleTestResult{
		Arch: runtime.GOARCH, Hidden: true, Restored: restored == original,
		NotEchoed:    before.position == after.position && slices.Equal(before.text, after.text),
		InputFlushed: nativeConsolePending(t, input) == 0,
		ContentOK:    string(actual.password) == expected, ErrorOK: errors.Is(actual.err, expectedError),
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s%s\n", nativeConsoleMarker, encoded)
}

func nativeConsoleOpen(t *testing.T, name string) windows.Handle {
	t.Helper()
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("cannot open helper's own console device: %v", err)
	}
	return handle
}

func nativeConsoleWaitHidden(t *testing.T, handle windows.Handle, results <-chan nativeConsoleReadResult) {
	t.Helper()
	deadline := time.Now().Add(nativeConsoleWait)
	for time.Now().Before(deadline) {
		var mode uint32
		if err := windows.GetConsoleMode(handle, &mode); err != nil {
			t.Fatal(err)
		}
		if mode&(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT) == 0 {
			return
		}
		select {
		case result := <-results:
			clear(result.password)
			t.Fatalf("native console reader returned before hiding input: %v", result.err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("native console echo was not disabled")
}

func nativeConsoleAssertPendingHidden(t *testing.T, handle windows.Handle, results <-chan nativeConsoleReadResult) {
	t.Helper()
	// Allow the reader to process the last event already dequeued from Win32.
	time.Sleep(75 * time.Millisecond)
	select {
	case result := <-results:
		clear(result.password)
		t.Fatal("native console reader ended before Enter, EOF or cancellation")
	default:
	}
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil || mode&(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT) != 0 {
		t.Fatal("native console restored echo while a password line was unfinished")
	}
}

func nativeConsoleWrite(t *testing.T, handle windows.Handle, text string) {
	t.Helper()
	nativeConsoleWriteUnits(t, handle, utf16.Encode([]rune(text)))
}

func nativeConsoleWriteUnits(t *testing.T, handle windows.Handle, characters []uint16) {
	t.Helper()
	records := make([]consoleInputRecord, len(characters))
	defer clear(records)
	for index, character := range characters {
		records[index] = consoleInputRecord{eventType: consoleKeyEvent, keyDown: 1, repeats: 1, character: character}
	}
	for len(records) > 0 {
		var written uint32
		ok, _, err := nativeConsoleTestWriteInput.Call(uintptr(handle), uintptr(unsafe.Pointer(&records[0])), uintptr(len(records)), uintptr(unsafe.Pointer(&written)))
		runtime.KeepAlive(records)
		if ok == 0 || written == 0 || written > uint32(len(records)) {
			t.Fatalf("cannot inject public fixture into helper's console: %v", err)
		}
		records = records[written:]
	}
}

func nativeConsolePending(t *testing.T, handle windows.Handle) uint32 {
	t.Helper()
	var count uint32
	ok, _, err := nativeConsoleTestInputCount.Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		t.Fatalf("cannot inspect helper's console queue: %v", err)
	}
	return count
}

func nativeConsoleWaitDrained(t *testing.T, handle windows.Handle) {
	t.Helper()
	deadline := time.Now().Add(nativeConsoleWait)
	for time.Now().Before(deadline) {
		if nativeConsolePending(t, handle) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("helper's native console input was not consumed")
}

func nativeConsoleSnapshot(t *testing.T, handle windows.Handle) nativeConsoleScreen {
	t.Helper()
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(handle, &info); err != nil {
		t.Fatal(err)
	}
	count := min(int(info.Size.X)*int(info.Size.Y), nativeConsoleScreenMax)
	if count <= 0 || int(info.CursorPosition.Y)*int(info.Size.X)+int(info.CursorPosition.X) >= count {
		t.Fatal("helper's console screen buffer is outside fixture bounds")
	}
	text := make([]uint16, count)
	var read uint32
	ok, _, err := nativeConsoleTestReadScreen.Call(uintptr(handle), uintptr(unsafe.Pointer(&text[0])), uintptr(count), 0, uintptr(unsafe.Pointer(&read)))
	runtime.KeepAlive(text)
	if ok == 0 || read != uint32(count) {
		t.Fatalf("cannot inspect helper's console echo output: %v", err)
	}
	return nativeConsoleScreen{position: info.CursorPosition, text: text}
}
