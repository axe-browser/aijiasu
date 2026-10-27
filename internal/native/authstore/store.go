// Package authstore persists private native-client profiles and sessions.
package authstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/privatefile"
)

const (
	maxPrivateFileBytes  = 64 * 1024
	maxSessionBytes      = 4 << 20
	maxSessionFieldBytes = 64 << 10
	maxStoredNodes       = 10000
	maxNodeFieldBytes    = 16 << 10
	sessionFileName      = "session.json"
	tempNameAttempts     = 10
)

// DefaultDirectory returns this application's directory under the user's
// configuration directory without creating or reading it.
func DefaultDirectory() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fileError("locate user configuration directory", err)
	}
	return filepath.Join(directory, "aijiasu-native"), nil
}

// LoadProfile reads a bounded private regular file. Protocol-specific field
// validation remains the responsibility of clientapi.NewClient.
func LoadProfile(path string) (profile clientapi.Profile, err error) {
	data, err := readPrivateFile(path, maxPrivateFileBytes)
	if err != nil {
		return profile, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&profile) != nil {
		return clientapi.Profile{}, errors.New("invalid private profile JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return clientapi.Profile{}, errors.New("private profile must contain one JSON object")
	}
	if profile.Version != 1 || profile.Endpoint == "" || profile.ClientVersion == "" || profile.SigningSeed == "" {
		return clientapi.Profile{}, errors.New("private profile requires version 1 and nonempty endpoint, client_version, and signing_seed")
	}
	return profile, nil
}

// readPrivateFile is also used by other bounded private configuration loaders.
// Errors never include filenames, JSON values or file contents.
func readPrivateFile(path string, maxBytes int) ([]byte, error) {
	return readCheckedPrivateFile(func() (os.FileInfo, error) { return os.Lstat(path) }, func() (*os.File, error) { return os.Open(path) }, maxBytes)
}

func readCheckedPrivateFile(inspect func() (os.FileInfo, error), open func() (*os.File, error), maxBytes int) (data []byte, err error) {
	info, err := inspect()
	if err != nil {
		return nil, fileError("inspect private file", err)
	}
	if err := checkPrivateFile(info, maxBytes); err != nil {
		return nil, err
	}
	file, err := open()
	if err != nil {
		return nil, fileError("open private file", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			data = nil
			err = errors.Join(err, fileError("close private file", closeErr))
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, fileError("inspect opened private file", err)
	}
	current, err := inspect()
	if err != nil {
		return nil, fileError("recheck private file", err)
	}
	if !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return nil, errors.New("private file changed while opening")
	}
	if err := checkPrivateFile(opened, maxBytes); err != nil {
		return nil, err
	}
	if err := checkPrivateFile(current, maxBytes); err != nil {
		return nil, err
	}
	if err := privatefile.CheckFile(file); err != nil {
		return nil, err
	}
	data, err = io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, fileError("read private file", err)
	}
	if len(data) > maxBytes {
		return nil, errors.New("private file exceeds size limit")
	}
	return data, nil
}

func checkPrivateFile(info os.FileInfo, maxBytes int) error {
	if !info.Mode().IsRegular() {
		return errors.New("private file must be a regular file without a symbolic link")
	}
	if !privatefile.PrivateMode(info, true) {
		return errors.New("private file must be owner-readable with no group or other permissions")
	}
	if info.Size() > int64(maxBytes) {
		return errors.New("private file exceeds size limit")
	}
	return nil
}

// sessionRecord is an explicit persistence allowlist, independent of future
// additions to the in-memory client API. Passwords and raw responses cannot fit.
type sessionRecord struct {
	Username        string            `json:"username"`
	LoginToken      string            `json:"login_token"`
	AuthenticatedAt time.Time         `json:"authenticated_at"`
	ExpireTime      json.Number       `json:"expire_time,omitempty"`
	ServiceUsername string            `json:"service_username,omitempty"`
	Nodes           []clientapi.Node  `json:"nodes,omitzero"`
	SyncVersion     map[string]string `json:"sync_version,omitempty"`
}

func sessionRecordFrom(session clientapi.Session) sessionRecord {
	return sessionRecord{session.Username, session.LoginToken, session.AuthenticatedAt, session.ExpireTime, session.ServiceUsername, normalizedNodeCache(session.Nodes, session.SyncVersion), session.SyncVersion}
}

func (record sessionRecord) session() clientapi.Session {
	return clientapi.Session{Username: record.Username, LoginToken: record.LoginToken, AuthenticatedAt: record.AuthenticatedAt, ExpireTime: record.ExpireTime, ServiceUsername: record.ServiceUsername, Nodes: normalizedNodeCache(record.Nodes, record.SyncVersion), SyncVersion: record.SyncVersion}
}

func normalizedNodeCache(nodes []clientapi.Node, versions map[string]string) []clientapi.Node {
	// Older writers omitted a successfully synced empty slice. Its Servers
	// version still distinguishes it from an original, unsynchronized session.
	if _, synced := versions["Servers"]; nodes == nil && synced {
		return []clientapi.Node{}
	}
	return nodes
}

// SaveSession atomically publishes understood reusable state. Existing
// directory permissions are never changed.
func SaveSession(directory string, session clientapi.Session) error {
	data, err := marshalSession(session)
	if err != nil {
		return err
	}
	root, err := openPrivateDirectory(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := acquireSessionLock(root)
	if err != nil {
		return err
	}
	defer releaseSessionLock(lock)
	if err := advanceSessionRevision(lock); err != nil {
		return err
	}
	return writeSession(root, data, root.Rename)
}

func marshalSession(session clientapi.Session) ([]byte, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	stored := sessionRecordFrom(session)
	data, err := json.Marshal(stored)
	if err != nil {
		return nil, errors.New("invalid session JSON fields")
	}
	if len(data) > maxSessionBytes {
		return nil, errors.New("session exceeds size limit")
	}
	return data, nil
}

func openPrivateDirectory(directory string) (*os.Root, error) {
	return openSessionDirectory(directory, true)
}

func openSessionDirectory(directory string, create bool) (*os.Root, error) {
	if create {
		if err := privatefile.MkdirAll(directory); err != nil {
			return nil, fileError("create private session directory", err)
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fileError("inspect private session directory", err)
	}
	if err := checkPrivateDirectory(info); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fileError("open private session directory", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, fileError("inspect opened session directory", err)
	}
	current, err := os.Lstat(directory)
	if err != nil {
		root.Close()
		return nil, fileError("recheck private session directory", err)
	}
	if !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		root.Close()
		return nil, errors.New("private session directory changed while opening")
	}
	if err := checkPrivateDirectory(current); err != nil {
		root.Close()
		return nil, err
	}
	if err := privatefile.CheckRoot(root); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

// LoadSession reads only a private, bounded, allowlisted session document.
// Older documents containing only the original four fields remain valid.
func LoadSession(directory string) (clientapi.Session, error) {
	root, err := openSessionDirectory(directory, false)
	if err != nil {
		return clientapi.Session{}, err
	}
	defer root.Close()
	return loadSession(root)
}

func loadSession(root *os.Root) (clientapi.Session, error) {
	data, err := readCheckedPrivateFile(func() (os.FileInfo, error) { return root.Lstat(sessionFileName) }, func() (*os.File, error) { return root.Open(sessionFileName) }, maxSessionBytes)
	if err != nil {
		return clientapi.Session{}, err
	}
	var stored sessionRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF {
		return clientapi.Session{}, errors.New("invalid private session JSON")
	}
	session := stored.session()
	if err := validateSession(session); err != nil {
		return clientapi.Session{}, err
	}
	return session, nil
}

// LogoutSession removes only session.json. It never creates the directory or
// follows a symbolic-link destination; profiles and other files are retained.
func LogoutSession(directory string) error {
	root, err := openSessionDirectory(directory, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := acquireSessionLock(root)
	if err != nil {
		return err
	}
	defer releaseSessionLock(lock)
	return logoutSession(root, lock)
}

func logoutSession(root *os.Root, lock *os.File) error {
	return logoutSessionContext(context.Background(), root, lock)
}

func logoutSessionContext(ctx context.Context, root *os.Root, lock *os.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	original, err := sessionInfo(root)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Even an already absent session must invalidate an earlier password login.
	if err := advanceSessionRevision(lock); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if original == nil {
		return nil
	}
	current, err := sessionInfo(root)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	if !os.SameFile(original, current) {
		return errors.New("session changed before removal")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Remove(sessionFileName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fileError("remove private session", err)
	}
	return nil
}

func validateSession(session clientapi.Session) error {
	if strings.TrimSpace(session.Username) == "" || strings.ContainsAny(session.Username, "\r\n\x00") || strings.TrimSpace(session.LoginToken) == "" {
		return errors.New("session requires a valid username and nonempty login token")
	}
	if len(session.Username) > maxSessionFieldBytes || len(session.LoginToken) > maxSessionFieldBytes || len(session.ServiceUsername) > maxSessionFieldBytes || len(session.Nodes) > maxStoredNodes || len(session.SyncVersion) > 256 {
		return errors.New("session exceeds resource limits")
	}
	// Bound the data before JSON escaping can allocate a buffer for it. The
	// serialized limit below remains authoritative for escaped Unicode/control
	// characters and object syntax.
	fieldBytes := len(session.Username) + len(session.LoginToken) + len(session.ServiceUsername) + len(session.ExpireTime)
	for _, node := range session.Nodes {
		if len(node.ID) > maxNodeFieldBytes || len(node.Title) > maxNodeFieldBytes || len(node.Status) > maxNodeFieldBytes || len(node.Host) > maxNodeFieldBytes || node.TCPPort < 0 || node.TCPPort > 65535 || node.UDPPort < 0 || node.UDPPort > 65535 {
			return errors.New("session has invalid node fields")
		}
		fieldBytes += len(node.ID) + len(node.Title) + len(node.Status) + len(node.Host)
		if fieldBytes > maxSessionBytes {
			return errors.New("session exceeds size limit")
		}
	}
	for key, value := range session.SyncVersion {
		if key == "" || len(key) > 128 || strings.ContainsAny(key, "[]&=\r\n\x00") || len(value) > maxNodeFieldBytes {
			return errors.New("session has invalid synchronization fields")
		}
		fieldBytes += len(key) + len(value)
		if fieldBytes > maxSessionBytes {
			return errors.New("session exceeds size limit")
		}
	}
	return nil
}

func checkPrivateDirectory(info os.FileInfo) error {
	if !info.IsDir() || !privatefile.PrivateMode(info, false) {
		return errors.New("session directory must be a private directory without a symbolic link")
	}
	return nil
}

// Passing the rename operation makes publication failures testable without
// changing filesystem permissions or depending on the process's privileges.
func writeSession(root *os.Root, data []byte, publish func(string, string) error) (err error) {
	return writeSessionContext(context.Background(), root, data, publish)
}

func writeSessionContext(ctx context.Context, root *os.Root, data []byte, publish func(string, string) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	original, err := sessionInfo(root)
	if err != nil {
		return err
	}
	file, name, err := createTemporarySession(root)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fileError("close temporary session", closeErr))
			}
		}
		if name != "" {
			if removeErr := root.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fileError("remove temporary session", removeErr))
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return fileError("write temporary session", err)
	}
	if err := file.Sync(); err != nil {
		return fileError("sync temporary session", err)
	}
	err = file.Close()
	file = nil
	if err != nil {
		return fileError("close temporary session", err)
	}
	current, err := sessionInfo(root)
	if err != nil {
		return err
	}
	if original == nil && current != nil || original != nil && (current == nil ||
		!os.SameFile(original, current) || original.Size() != current.Size() ||
		!original.ModTime().Equal(current.ModTime())) {
		return errors.New("session changed before publication")
	}
	directoryInfo, err := root.Stat(".")
	if err != nil {
		return fileError("recheck session directory permissions", err)
	}
	if err := checkPrivateDirectory(directoryInfo); err != nil {
		return err
	}
	if err := privatefile.CheckRoot(root); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publish(name, sessionFileName); err != nil {
		return fileError("publish private session", err)
	}
	name = ""
	return nil
}

func sessionInfo(root *os.Root) (os.FileInfo, error) {
	info, err := root.Lstat(sessionFileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fileError("inspect session file", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("session file must be a regular file without a symbolic link")
	}
	return info, nil
}

func createTemporarySession(root *os.Root) (*os.File, string, error) {
	for attempt := 0; attempt < tempNameAttempts; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", errors.New("cannot generate temporary session name")
		}
		name := ".session-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fileError("create temporary session", err)
		}
		if err := privatefile.CheckFile(file); err != nil {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", err
		}
		return file, name, nil
	}
	return nil, "", errors.New("cannot allocate temporary session file")
}

func fileError(operation string, err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		err = pathError.Err
	}
	var linkError *os.LinkError
	if errors.As(err, &linkError) {
		err = linkError.Err
	}
	return fmt.Errorf("%s: %w", operation, err)
}
