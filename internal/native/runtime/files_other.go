//go:build !darwin && !linux && !windows

package runtime

import (
	"errors"
	"os"
	"syscall"
)

func privateLockFlags() int        { return os.O_RDWR | os.O_CREATE }
func lockExclusive(*os.File) error { return errors.New("native runtime requires macOS or Linux") }
func unlock(*os.File) error        { return nil }

func secureRuntimeSocket(root *os.Root, _ string) error { return root.Chmod(socketName, 0o600) }
func privateRuntimeSocketMode(info os.FileInfo) bool    { return info.Mode().Perm() == 0o600 }
func runtimeConnectionRefused(err error) bool           { return errors.Is(err, syscall.ECONNREFUSED) }
