package authstore

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"sync"

	"aijiasu-native/internal/native/clientapi"
)

const sessionRevisionBytes = 16

// LoginVersion also records absence: a logout must invalidate a pending first
// login even when there was no session.json to remove. The revision lives in the
// existing lock file, independently of the session document's compatible format.
type LoginVersion struct {
	directory os.FileInfo
	file      os.FileInfo
	lock      os.FileInfo
	revision  [sessionRevisionBytes]byte
}

// BeginLogin captures state without holding a filesystem lock over the request.
func BeginLogin(directory string) (LoginVersion, error) {
	return BeginLoginContext(context.Background(), directory)
}

// BeginLoginContext permits interruption while capturing the pre-request state.
func BeginLoginContext(ctx context.Context, directory string) (LoginVersion, error) {
	if ctx == nil {
		return LoginVersion{}, errors.New("session operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return LoginVersion{}, err
	}
	root, err := openPrivateDirectory(directory)
	if err != nil {
		return LoginVersion{}, err
	}
	defer root.Close()
	lock, err := acquireSessionLockContext(ctx, root)
	if err != nil {
		return LoginVersion{}, err
	}
	defer releaseSessionLock(lock)
	version := LoginVersion{}
	if version.directory, err = root.Stat("."); err != nil {
		return LoginVersion{}, fileError("inspect login directory", err)
	}
	if version.file, err = sessionInfo(root); err != nil {
		return LoginVersion{}, err
	}
	if version.lock, err = lock.Stat(); err != nil {
		return LoginVersion{}, fileError("inspect login lock", err)
	}
	version.revision, err = readSessionRevision(lock)
	if err := ctx.Err(); err != nil {
		return LoginVersion{}, err
	}
	return version, err
}

// SaveLoginSession discards a late response after any saved login, refresh or
// logout, including logout of an empty directory. The first committed operation
// wins when several password requests observed the same state.
func SaveLoginSession(directory string, version LoginVersion, session clientapi.Session) error {
	return SaveLoginSessionContext(context.Background(), directory, version, session)
}

// SaveLoginSessionContext cancels both waiting for the commit lock and preparing
// the atomic publication. An already saved session is preserved on interruption.
func SaveLoginSessionContext(ctx context.Context, directory string, version LoginVersion, session clientapi.Session) error {
	if ctx == nil {
		return errors.New("session commit context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if version.directory == nil || version.lock == nil {
		return ErrSessionChanged
	}
	data, err := marshalSession(session)
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
	directoryInfo, err := root.Stat(".")
	if err != nil {
		return fileError("inspect login commit directory", err)
	}
	lockInfo, err := lock.Stat()
	if err != nil {
		return fileError("inspect login commit lock", err)
	}
	current, err := sessionInfo(root)
	if err != nil {
		return err
	}
	revision, err := readSessionRevision(lock)
	if err != nil {
		return err
	}
	sameFile := version.file == nil && current == nil || version.file != nil && sameSessionVersion(version.file, current)
	if !os.SameFile(version.directory, directoryInfo) || !os.SameFile(version.lock, lockInfo) || !sameFile || revision != version.revision {
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

// LockSessionLifecycle serializes registration of a worker with logout. Startup
// releases this lock once its control socket is served, before network work;
// logout retains it until stopping that worker and removing the session finish.
func LockSessionLifecycle(directory string) (func(), error) {
	return LockSessionLifecycleContext(context.Background(), directory)
}

// LockSessionLifecycleContext makes worker registration's lock wait cancelable.
func LockSessionLifecycleContext(ctx context.Context, directory string) (func(), error) {
	if ctx == nil {
		return nil, errors.New("session operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := openPrivateDirectory(directory)
	if err != nil {
		return nil, err
	}
	lock, err := acquireSessionLockContext(ctx, root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		releaseSessionLock(lock)
		_ = root.Close()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			releaseSessionLock(lock)
			_ = root.Close()
		})
	}, nil
}

// LogoutSessionAfterStop makes worker stopping and session removal one ordered
// operation. Creating the private lock also closes the first-login/no-directory
// window; standalone LogoutSession keeps its historical no-create behavior.
func LogoutSessionAfterStop(directory string, stop func() error) error {
	return LogoutSessionAfterStopContext(context.Background(), directory, stop)
}

// LogoutSessionAfterStopContext stops on cancellation before invoking stop or
// removing the session. Cancellation after a completed removal is a normal race.
func LogoutSessionAfterStopContext(ctx context.Context, directory string, stop func() error) error {
	if ctx == nil {
		return errors.New("session operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stop == nil {
		return errors.New("logout requires a worker stop operation")
	}
	root, err := openPrivateDirectory(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := acquireSessionLockContext(ctx, root)
	if err != nil {
		return err
	}
	defer releaseSessionLock(lock)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := stop(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return logoutSessionContext(ctx, root, lock)
}

func readSessionRevision(lock *os.File) ([sessionRevisionBytes]byte, error) {
	var revision [sessionRevisionBytes]byte
	data, err := io.ReadAll(io.NewSectionReader(lock, 0, sessionRevisionBytes+1))
	if err != nil {
		return revision, fileError("read session revision", err)
	}
	// Empty lock files from earlier clients represent the initial revision.
	if len(data) != 0 && len(data) != len(revision) {
		return revision, errors.New("invalid session revision")
	}
	copy(revision[:], data)
	return revision, nil
}

func advanceSessionRevision(lock *os.File) error {
	var revision [sessionRevisionBytes]byte
	if _, err := rand.Read(revision[:]); err != nil {
		return errors.New("cannot create session revision")
	}
	if _, err := lock.WriteAt(revision[:], 0); err != nil {
		return fileError("update session revision", err)
	}
	if err := lock.Truncate(int64(len(revision))); err != nil {
		return fileError("truncate session revision", err)
	}
	if err := lock.Sync(); err != nil {
		return fileError("sync session revision", err)
	}
	return nil
}
