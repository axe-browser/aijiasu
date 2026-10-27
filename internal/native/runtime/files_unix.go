//go:build darwin || linux

package runtime

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func privateLockFlags() int { return os.O_RDWR | os.O_CREATE | unix.O_NOFOLLOW }
func lockExclusive(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("runtime is already running or its lock is unavailable")
	}
	return nil
}
func unlock(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }

func secureRuntimeSocket(root *os.Root, _ string) error { return root.Chmod(socketName, 0o600) }
func privateRuntimeSocketMode(info os.FileInfo) bool    { return info.Mode().Perm() == 0o600 }
func runtimeConnectionRefused(err error) bool           { return errors.Is(err, syscall.ECONNREFUSED) }
