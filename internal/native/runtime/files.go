package runtime

import (
	"errors"
	"net"
	"os"
	"path/filepath"

	"aijiasu-native/internal/native/privatefile"
)

const socketName = "runtime.sock"
const lockName = "runtime.lock"
const maxSocketPathBytes = 100

type runtimeDirectory struct {
	path       string
	root       *os.Root
	lock       *os.File
	info       os.FileInfo
	socketInfo os.FileInfo
	listener   *net.UnixListener
}

func runtimeDirectoryPath(directory string) (string, error) {
	if directory == "" {
		return "", errors.New("runtime directory is required")
	}
	path, err := filepath.Abs(directory)
	if err != nil {
		return "", safeFailure("runtime socket path is invalid or too long", err)
	}
	if len(filepath.Join(path, socketName)) > maxSocketPathBytes {
		return "", errors.New("runtime socket path is invalid or too long")
	}
	return path, nil
}

func openRuntimeDirectory(directory string) (*runtimeDirectory, error) {
	path, err := runtimeDirectoryPath(directory)
	if err != nil {
		return nil, err
	}
	if err := privatefile.MkdirAll(path); err != nil {
		return nil, errors.New("cannot create runtime directory")
	}
	root, info, err := openExistingDirectory(path)
	if err != nil {
		return nil, err
	}
	directoryState := &runtimeDirectory{path: path, root: root, info: info}
	before, err := root.Lstat(lockName)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, errors.New("cannot inspect runtime lock")
	}
	if before != nil && (!before.Mode().IsRegular() || !privatefile.PrivateMode(before, false)) {
		root.Close()
		return nil, errors.New("runtime lock must be a private regular file")
	}
	file, err := root.OpenFile(lockName, privateLockFlags(), 0o600)
	if err != nil {
		root.Close()
		return nil, errors.New("cannot open runtime lock")
	}
	opened, statErr := file.Stat()
	current, currentErr := root.Lstat(lockName)
	if statErr != nil || currentErr != nil || !opened.Mode().IsRegular() || !privatefile.PrivateMode(opened, false) || !os.SameFile(opened, current) || before != nil && !os.SameFile(before, opened) || privatefile.CheckFile(file) != nil {
		file.Close()
		root.Close()
		return nil, errors.New("runtime lock changed or has unsafe permissions")
	}
	if err := lockExclusive(file); err != nil {
		file.Close()
		root.Close()
		return nil, err
	}
	directoryState.lock = file
	return directoryState, nil
}

func openExistingDirectory(path string) (*os.Root, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrNotRunning
	}
	if err != nil || !info.IsDir() || !privatefile.PrivateMode(info, false) {
		return nil, nil, errors.New("runtime directory must be private and not a symbolic link")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, errors.New("cannot open private runtime directory")
	}
	opened, openedErr := root.Stat(".")
	current, currentErr := os.Lstat(path)
	if openedErr != nil || currentErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, current) || !current.IsDir() || !privatefile.PrivateMode(current, false) || privatefile.CheckRoot(root) != nil {
		root.Close()
		return nil, nil, errors.New("runtime directory changed while opening")
	}
	return root, info, nil
}

func (directory *runtimeDirectory) bindSocket() (*net.UnixListener, error) {
	old, err := directory.root.Lstat(socketName)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot inspect runtime socket")
	}
	if old != nil {
		if old.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("runtime socket path contains another file")
		}
		if err := directory.root.Remove(socketName); err != nil {
			return nil, errors.New("cannot remove stale runtime socket")
		}
	}
	current, err := os.Lstat(directory.path)
	if err != nil || !os.SameFile(directory.info, current) {
		return nil, errors.New("runtime directory changed before socket creation")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory.path, socketName), Net: "unix"})
	if err != nil {
		return nil, errors.New("cannot bind private runtime socket")
	}
	listener.SetUnlinkOnClose(false)
	directory.listener = listener
	directory.socketInfo, err = directory.root.Lstat(socketName)
	if err != nil {
		listener.Close()
		return nil, errors.New("cannot inspect created runtime socket")
	}
	if err := secureRuntimeSocket(directory.root, filepath.Join(directory.path, socketName)); err != nil {
		directory.closeSocket()
		return nil, errors.New("cannot secure runtime socket")
	}
	return listener, nil
}

func (directory *runtimeDirectory) closeSocket() {
	if directory.listener != nil {
		_ = directory.listener.Close()
	}
	if directory.socketInfo != nil {
		current, err := directory.root.Lstat(socketName)
		if err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(directory.socketInfo, current) {
			_ = directory.root.Remove(socketName)
		}
	}
}

func (directory *runtimeDirectory) close() {
	directory.closeSocket()
	if directory.lock != nil {
		_ = unlock(directory.lock)
		_ = directory.lock.Close()
	}
	_ = directory.root.Close()
}
