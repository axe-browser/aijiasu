//go:build darwin || linux

package nodemgr

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func stateLockFlags() int { return os.O_RDWR | os.O_CREATE | unix.O_NOFOLLOW }
func lockStateContext(ctx context.Context, file *os.File, exclusive bool) error {
	operation := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		operation = unix.LOCK_EX | unix.LOCK_NB
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(file.Fd()), operation)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return errors.New("cannot acquire private node-state lock")
		}
		if !time.Now().Before(deadline) {
			return errors.New("node state is busy; retry the operation")
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func unlockState(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
