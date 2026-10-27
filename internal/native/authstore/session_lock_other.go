//go:build !darwin && !linux && !windows

package authstore

import (
	"context"
	"errors"
	"os"
)

func sessionLockFlags() int { return os.O_RDWR | os.O_CREATE }
func lockSession(*os.File) error {
	return errors.New("private session locking requires macOS or Linux")
}
func lockSessionContext(ctx context.Context, file *os.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return lockSession(file)
}
func unlockSession(*os.File) error { return nil }
