package main

import (
	"errors"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

const (
	terminalGetStateRequest = unix.TCGETS
	terminalSetStateRequest = unix.TCSETS
)

func flushTerminalInput(fd int) error {
	for {
		err := unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
		if err != unix.EINTR {
			return err
		}
	}
}

func terminalReadyOnce(fd int, wait time.Duration) (bool, error) {
	if fd < 0 {
		return false, unix.EBADF
	}
	buffer := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	milliseconds := int((wait + time.Millisecond - 1) / time.Millisecond)
	n, err := unix.Poll(buffer, milliseconds)
	if err != nil || n == 0 {
		return false, err
	}
	if buffer[0].Revents&unix.POLLNVAL != 0 {
		return false, unix.EBADF
	}
	if buffer[0].Revents&unix.POLLERR != 0 {
		return false, errors.New("password terminal reported an input error")
	}
	if buffer[0].Revents&unix.POLLIN != 0 {
		return true, nil
	}
	if buffer[0].Revents&unix.POLLHUP != 0 {
		return false, io.EOF
	}
	return false, nil
}
