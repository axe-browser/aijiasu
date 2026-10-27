package nodemgr

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func stateLockFlags() int { return os.O_RDWR | os.O_CREATE }

func lockStateContext(ctx context.Context, file *os.File, exclusive bool) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &windows.Overlapped{})
		if err == nil {
			if err := ctx.Err(); err != nil {
				_ = unlockState(file)
				return err
			}
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return errors.New("cannot acquire private node-state lock")
		}
		if !time.Now().Before(deadline) {
			return errors.New("node state is busy; retry the operation")
		}
		timer := time.NewTimer(min(5*time.Millisecond, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func unlockState(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
