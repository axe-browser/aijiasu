//go:build !darwin && !linux && !windows

package nodemgr

import (
	"context"
	"errors"
	"os"
)

func stateLockFlags() int { return os.O_RDWR | os.O_CREATE }
func lockStateContext(ctx context.Context, _ *os.File, _ bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("private node-state locking requires macOS or Linux")
}
func unlockState(*os.File) error { return nil }
