package authstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/privatefile"
)

var ErrSessionChanged = errors.New("login session changed during operation")

// SessionVersion identifies the file read before a refresh request. It contains
// no token or account data, and is only valid for this private directory.
type SessionVersion struct {
	directory os.FileInfo
	file      os.FileInfo
}

// VersionOfSession rejects a stale caller snapshot before any network request.
// No filesystem lock is retained while waiting for the service response.
func VersionOfSession(directory string, expected clientapi.Session) (SessionVersion, error) {
	return VersionOfSessionContext(context.Background(), directory, expected)
}

// VersionOfSessionContext permits interruption before the refresh is sent.
func VersionOfSessionContext(ctx context.Context, directory string, expected clientapi.Session) (SessionVersion, error) {
	if ctx == nil {
		return SessionVersion{}, errors.New("session operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return SessionVersion{}, err
	}
	expectedData, err := marshalSession(expected)
	if err != nil {
		return SessionVersion{}, err
	}
	defer clear(expectedData)
	if err := ctx.Err(); err != nil {
		return SessionVersion{}, err
	}
	root, err := openSessionDirectory(directory, false)
	if err != nil {
		return SessionVersion{}, err
	}
	defer root.Close()
	lock, err := acquireSessionLockContext(ctx, root)
	if err != nil {
		return SessionVersion{}, err
	}
	defer releaseSessionLock(lock)
	current, err := loadSession(root)
	if err != nil {
		return SessionVersion{}, err
	}
	currentData, err := marshalSession(current)
	if err != nil {
		return SessionVersion{}, err
	}
	defer clear(currentData)
	if !bytes.Equal(expectedData, currentData) {
		return SessionVersion{}, ErrSessionChanged
	}
	info, err := sessionInfo(root)
	if err != nil {
		return SessionVersion{}, err
	}
	directoryInfo, err := root.Stat(".")
	if err != nil {
		return SessionVersion{}, fileError("inspect session version directory", err)
	}
	if info == nil {
		return SessionVersion{}, ErrSessionChanged
	}
	if err := ctx.Err(); err != nil {
		return SessionVersion{}, err
	}
	return SessionVersion{directory: directoryInfo, file: info}, nil
}

// SaveRefreshedSession commits only if no login, logout, or other refresh has
// replaced the captured session. Login and logout use the same cross-process lock.
func SaveRefreshedSession(directory string, version SessionVersion, updated clientapi.Session) error {
	return SaveRefreshedSessionContext(context.Background(), directory, version, updated)
}

// SaveRefreshedSessionContext also cancels lock waiting and checks cancellation
// before publication, so an interrupted command cannot later save its response.
func SaveRefreshedSessionContext(ctx context.Context, directory string, version SessionVersion, updated clientapi.Session) error {
	if ctx == nil {
		return errors.New("session commit context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if version.directory == nil || version.file == nil {
		return ErrSessionChanged
	}
	data, err := marshalSession(updated)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := openSessionDirectory(directory, false)
	if errors.Is(err, os.ErrNotExist) {
		return ErrSessionChanged
	}
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := acquireSessionLockContext(ctx, root)
	if err != nil {
		return err
	}
	defer releaseSessionLock(lock)
	current, err := sessionInfo(root)
	if err != nil {
		return err
	}
	directoryInfo, err := root.Stat(".")
	if err != nil {
		return fileError("inspect refresh session directory", err)
	}
	if !os.SameFile(version.directory, directoryInfo) || !sameSessionVersion(version.file, current) {
		return ErrSessionChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := advanceSessionRevision(lock); err != nil {
		return err
	}
	return writeSessionContext(ctx, root, data, root.Rename)
}

func sameSessionVersion(expected, current os.FileInfo) bool {
	return current != nil && os.SameFile(expected, current) && expected.Size() == current.Size() && expected.ModTime().Equal(current.ModTime())
}

const (
	sessionLockName         = "session.lock"
	sessionLockOpenAttempts = 5
	sessionLockRetryDelay   = 5 * time.Millisecond
	sessionLockWait         = 2 * time.Second
)

func acquireSessionLock(root *os.Root) (*os.File, error) {
	return acquireSessionLockContext(context.Background(), root)
}

func acquireSessionLockContext(ctx context.Context, root *os.Root) (*os.File, error) {
	var observed os.FileInfo
	for attempt := 0; attempt < sessionLockOpenAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before, err := root.Lstat(sessionLockName)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fileError("inspect private session lock", err)
		}
		if before != nil && (!before.Mode().IsRegular() || !privatefile.PrivateMode(before, false)) {
			return nil, errors.New("session lock must be a private regular file")
		}
		if observed != nil && (before == nil || !os.SameFile(observed, before)) {
			return nil, errors.New("session lock changed while opening")
		}
		observed = before
		file, err := root.OpenFile(sessionLockName, sessionLockFlags(), 0o600)
		if err != nil {
			// Concurrent first creation can transiently fail through os.Root on macOS.
			if errors.Is(err, os.ErrNotExist) && attempt+1 < sessionLockOpenAttempts {
				timer := time.NewTimer(sessionLockRetryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, ctx.Err()
				case <-timer.C:
				}
				continue
			}
			return nil, fileError("open private session lock", err)
		}
		opened, statErr := file.Stat()
		current, currentErr := root.Lstat(sessionLockName)
		if statErr != nil || currentErr != nil || !opened.Mode().IsRegular() || !privatefile.PrivateMode(opened, false) || !os.SameFile(opened, current) || before != nil && !os.SameFile(before, opened) {
			_ = file.Close()
			return nil, errors.New("session lock changed while opening")
		}
		if err := privatefile.CheckFile(file); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := lockSessionContext(ctx, file); err != nil {
			_ = file.Close()
			return nil, err
		}
		return file, nil
	}
	return nil, errors.New("cannot open private session lock")
}

func releaseSessionLock(file *os.File) {
	_ = unlockSession(file)
	_ = file.Close()
}
