package main

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	consoleKeyEvent      = 0x0001
	consolePollMillis    = 50
	consoleEventsPerRead = 16
)

var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

// INPUT_RECORD has a four-byte header and a sixteen-byte event union.
type consoleInputRecord struct {
	eventType uint16
	_         uint16
	keyDown   int32
	repeats   uint16
	keyCode   uint16
	scanCode  uint16
	character uint16
	control   uint32
}

type windowsPasswordConsole struct{ handle windows.Handle }

func readTerminalPassword(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString("CONIN$")
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open password console: %w", err)
	}
	return readConsolePassword(ctx, &windowsPasswordConsole{handle: handle})
}

func (console *windowsPasswordConsole) hideInput() (func() error, error) {
	var original uint32
	if err := windows.GetConsoleMode(console.handle, &original); err != nil {
		return nil, err
	}
	hidden := original &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT |
		windows.ENABLE_QUICK_EDIT_MODE | windows.ENABLE_VIRTUAL_TERMINAL_INPUT)
	hidden |= windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_EXTENDED_FLAGS
	if err := windows.SetConsoleMode(console.handle, hidden); err != nil {
		return nil, err
	}
	return func() error { return windows.SetConsoleMode(console.handle, original) }, nil
}

func (console *windowsPasswordConsole) readKeys(ctx context.Context) ([]consolePasswordKey, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ready, err := windows.WaitForSingleObject(console.handle, consolePollMillis)
		if err != nil {
			return nil, err
		}
		if ready == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		if ready != windows.WAIT_OBJECT_0 {
			return nil, fmt.Errorf("unexpected console wait result: %d", ready)
		}
		var records [consoleEventsPerRead]consoleInputRecord
		var count uint32
		ok, _, callErr := readConsoleInput.Call(uintptr(console.handle), uintptr(unsafe.Pointer(&records[0])),
			uintptr(len(records)), uintptr(unsafe.Pointer(&count)))
		if ok == 0 {
			clear(records[:])
			if callErr == syscall.Errno(0) {
				callErr = windows.ERROR_GEN_FAILURE
			}
			return nil, callErr
		}
		if count > uint32(len(records)) {
			clear(records[:])
			return nil, fmt.Errorf("invalid console event count")
		}
		keys := make([]consolePasswordKey, 0, count)
		for _, record := range records[:count] {
			if record.eventType == consoleKeyEvent && record.keyDown != 0 && record.character != 0 {
				keys = append(keys, consolePasswordKey{character: record.character, repeats: record.repeats})
			}
		}
		clear(records[:])
		return keys, nil
	}
}

func (console *windowsPasswordConsole) flushInput() error {
	return windows.FlushConsoleInputBuffer(console.handle)
}

func (console *windowsPasswordConsole) Close() error { return windows.CloseHandle(console.handle) }
