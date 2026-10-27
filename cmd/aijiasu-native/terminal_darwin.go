package main

import (
	"time"

	"golang.org/x/sys/unix"
)

const (
	terminalGetStateRequest = unix.TIOCGETA
	terminalSetStateRequest = unix.TIOCSETA
	terminalFlushRead       = 1 // Darwin FREAD selector for TIOCFLUSH.
)

func flushTerminalInput(fd int) error {
	for {
		err := unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, terminalFlushRead)
		if err != unix.EINTR {
			return err
		}
	}
}

func terminalReadyOnce(fd int, wait time.Duration) (bool, error) {
	// Darwin's /dev/tty can report POLLNVAL to poll even for a valid descriptor.
	// select supports that character device and retains the same bounded wait.
	if fd < 0 || fd >= unix.FD_SETSIZE {
		return false, unix.EBADF
	}
	var readable unix.FdSet
	readable.Set(fd)
	timeout := unix.NsecToTimeval(wait.Nanoseconds())
	n, err := unix.Select(fd+1, &readable, nil, nil, &timeout)
	return n > 0 && readable.IsSet(fd), err
}
