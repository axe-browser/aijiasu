package authstore

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func sessionLockFlags() int { return os.O_RDWR | os.O_CREATE }

func lockSession(file *os.File) error { return lockSessionContext(context.Background(), file) }

func lockSessionContext(ctx context.Context, file *os.File) error {
	deadline := time.Now().Add(sessionLockWait)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
		if err == nil {
			if err := ctx.Err(); err != nil {
				_ = unlockSession(file)
				return err
			}
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fileError("lock private session", err)
		}
		if !time.Now().Before(deadline) {
			return errors.New("login session is busy; retry the operation")
		}
		timer := time.NewTimer(min(sessionLockRetryDelay, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func unlockSession(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
