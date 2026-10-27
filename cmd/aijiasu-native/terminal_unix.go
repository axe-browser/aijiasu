//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	terminalPollInterval = 50 * time.Millisecond
	terminalReadBytes    = 256
)

type terminalFile interface {
	Fd() uintptr
	Close() error
}

type terminalDescriptor struct {
	fd int
}

func (terminal terminalDescriptor) Fd() uintptr  { return uintptr(terminal.fd) }
func (terminal terminalDescriptor) Close() error { return unix.Close(terminal.fd) }

type terminalOperations struct {
	open         func() (terminalFile, error)
	getState     func(int) (*unix.Termios, error)
	setState     func(int, *unix.Termios) error
	flushInput   func(int) error
	waitReadable func(context.Context, int) error
	read         func(int, []byte) (int, error)
}

func readTerminalPassword(ctx context.Context) ([]byte, error) {
	return readTerminalPasswordWith(ctx, terminalOperations{
		open: func() (terminalFile, error) {
			fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil, err
			}
			return terminalDescriptor{fd: fd}, nil
		},
		getState: func(fd int) (*unix.Termios, error) {
			return unix.IoctlGetTermios(fd, terminalGetStateRequest)
		},
		setState: func(fd int, state *unix.Termios) error {
			for {
				err := unix.IoctlSetTermios(fd, terminalSetStateRequest, state)
				if !errors.Is(err, unix.EINTR) {
					return err
				}
			}
		},
		flushInput:   flushTerminalInput,
		waitReadable: waitTerminalReadable,
		read:         unix.Read,
	})
}

func readTerminalPasswordWith(ctx context.Context, operations terminalOperations) (password []byte, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	terminal, err := operations.open()
	if err != nil {
		return nil, fmt.Errorf("open password terminal: %w", err)
	}
	defer func() {
		if err := terminal.Close(); err != nil {
			clear(password)
			password = nil
			resultErr = errors.Join(resultErr, fmt.Errorf("close password terminal: %w", err))
		}
	}()
	fd := int(terminal.Fd())
	state, err := operations.getState(fd)
	if err != nil {
		return nil, fmt.Errorf("read terminal state: %w", err)
	}
	defer func() {
		// Discard unfinished password input before restoring echo. The immediate
		// state ioctl and raw nonblocking descriptor never wait for a reader.
		flushErr := operations.flushInput(fd)
		restoreErr := operations.setState(fd, state)
		if restoreErr == nil && state.Lflag&unix.ICANON != 0 && state.Lflag&unix.PENDIN == 0 {
			// Darwin can requeue input and set PENDIN when canonical mode is
			// restored. Clear that synthetic state and any remaining input too.
			restoreErr = operations.flushInput(fd)
		}
		if flushErr != nil || restoreErr != nil {
			clear(password)
			password = nil
			resultErr = errors.Join(resultErr, errTerminalRestore, flushErr, restoreErr)
		}
	}()
	hidden := *state
	// Canonical input can stop accepting a line at the OS queue limit, before
	// our 4 KiB bound. Read incrementally and implement the line edits ourselves.
	hidden.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.IEXTEN
	hidden.Lflag |= unix.ISIG
	hidden.Iflag &^= unix.IXON | unix.IXOFF | unix.INLCR | unix.IGNCR | unix.ISTRIP
	hidden.Iflag |= unix.ICRNL
	hidden.Cc[unix.VMIN], hidden.Cc[unix.VTIME] = 1, 0
	if err := operations.setState(fd, &hidden); err != nil {
		return nil, fmt.Errorf("disable terminal echo: %w", err)
	}
	buffer := make([]byte, terminalReadBytes)
	defer clear(buffer)
	input := make([]byte, 0, maxPasswordBytes)
	oversize := false
	defer func() {
		if resultErr != nil {
			clear(input)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := operations.waitReadable(ctx, fd); err != nil {
			return nil, err
		}
		n, err := operations.read(fd, buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read password terminal: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n == 0 {
			if oversize {
				return nil, errPasswordTooLong
			}
			return nil, io.EOF
		}
		for _, character := range buffer[:n] {
			switch {
			case character == '\r' || character == '\n':
				if oversize {
					return nil, errPasswordTooLong
				}
				if len(input) == 0 {
					return nil, errPasswordEmpty
				}
				return input, nil
			case terminalControl(character, state.Cc[unix.VEOF]):
				if oversize {
					return nil, errPasswordTooLong
				}
				if len(input) == 0 {
					return nil, io.EOF
				}
				return input, nil
			case oversize:
				// Keep echo disabled until this rejected line ends, including a
				// slowly arriving paste tail. Editing cannot make it valid again.
				continue
			case character == '\b' || character == '\x7f' || terminalControl(character, state.Cc[unix.VERASE]):
				if len(input) > 0 {
					_, size := utf8.DecodeLastRune(input)
					start := len(input) - size
					clear(input[start:])
					input = input[:start]
				}
			case terminalControl(character, state.Cc[unix.VKILL]):
				clear(input)
				input = input[:0]
			default:
				if len(input) == maxPasswordBytes {
					clear(input)
					input = input[:0]
					oversize = true
					continue
				}
				input = append(input, character)
			}
		}
		clear(buffer[:n])
	}
}

func terminalControl(character, configured byte) bool {
	// Unix variants use NUL or 0xff to disable a special input character.
	return configured != 0 && configured != 0xff && character == configured
}

func waitTerminalReadable(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := terminalPollInterval
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining < wait {
				wait = remaining
			}
		}
		if wait <= 0 {
			return context.DeadlineExceeded
		}
		ready, err := terminalReadyOnce(fd, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for password terminal: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if ready {
			return nil
		}
	}
}
