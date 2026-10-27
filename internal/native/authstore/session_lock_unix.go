//go:build darwin || linux

package authstore

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func sessionLockFlags() int { return os.O_RDWR | os.O_CREATE | unix.O_NOFOLLOW }

func lockSession(file *os.File) error {
	return lockSessionContext(context.Background(), file)
}

func lockSessionContext(ctx context.Context, file *os.File) error {
	deadline := time.Now().Add(sessionLockWait)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			if err := ctx.Err(); err != nil {
				_ = unlockSession(file)
				return err
			}
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
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

func unlockSession(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
