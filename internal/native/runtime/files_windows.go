package runtime

import (
	"errors"
	"os"

	"aijiasu-native/internal/native/privatefile"

	"golang.org/x/sys/windows"
)

func privateLockFlags() int { return os.O_RDWR | os.O_CREATE }

func lockExclusive(file *os.File) error {
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		return errors.New("runtime is already running or its lock is unavailable")
	}
	return nil
}

func unlock(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}

func secureRuntimeSocket(_ *os.Root, path string) error { return privatefile.CheckPath(path) }
func privateRuntimeSocketMode(info os.FileInfo) bool    { return privatefile.PrivateMode(info, true) }
func runtimeConnectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
