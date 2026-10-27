package authstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/privatefile"
)

func publicProfile() clientapi.Profile {
	return clientapi.Profile{
		Version: 1, Endpoint: "https://example.test/client.php", ClientVersion: "offline-test",
		SigningSeed: "public-test-seed", CommonParameters: map[string]string{"_m": "test"},
	}
}

func publicSession() clientapi.Session {
	return clientapi.Session{
		Username: "public-user", LoginToken: "public-test-token",
		AuthenticatedAt: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), ExpireTime: json.Number("1800000000"),
	}
}

func TestLoadSessionOriginalAndExtendedAllowlist(t *testing.T) {
	for _, extended := range []bool{false, true} {
		directory := privateDirectory(t)
		want := publicSession()
		if extended {
			want.ServiceUsername = "canonical-public-user"
			want.Nodes = []clientapi.Node{{ID: "1", Title: "公开节点", Status: "unknown", Host: "example.test", TCPPort: 443, UDPPort: 10000}}
			want.SyncVersion = map[string]string{"Login": "1", "Servers": "2"}
		}
		if err := SaveSession(directory, want); err != nil {
			t.Fatal(err)
		}
		got, err := LoadSession(directory)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if string(wantJSON) != string(gotJSON) {
			t.Fatal("private session did not round-trip its allowlisted fields")
		}
		data, err := os.ReadFile(filepath.Join(directory, sessionFileName))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"password", "signing_seed", "raw_response", "common_parameters"} {
			if strings.Contains(string(data), forbidden) {
				t.Fatal("session persisted a forbidden field")
			}
		}
	}
}

func TestLoadSessionPrivateFileAndDirectoryChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix owner permissions")
	}
	for _, mode := range []os.FileMode{0o400, 0o600, 0o640, 0o604, 0o200} {
		directory := privateDirectory(t)
		if err := SaveSession(directory, publicSession()); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, sessionFileName)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSession(directory)
		if (mode == 0o400 || mode == 0o600) != (err == nil) {
			t.Fatalf("mode %o had unexpected load result: %v", mode, err)
		}
	}
	for _, kind := range []string{"linked file", "directory file", "public directory", "linked directory"} {
		directory := privateDirectory(t)
		if err := SaveSession(directory, publicSession()); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, sessionFileName)
		switch kind {
		case "linked file":
			target := filepath.Join(t.TempDir(), "target.json")
			data, _ := json.Marshal(publicSession())
			if err := os.WriteFile(target, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skip("symbolic links unavailable")
			}
		case "directory file":
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		case "public directory":
			if err := os.Chmod(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		case "linked directory":
			link := filepath.Join(t.TempDir(), "linked")
			if err := os.Symlink(directory, link); err != nil {
				t.Skip("symbolic links unavailable")
			}
			directory = link
		}
		if _, err := LoadSession(directory); err == nil {
			t.Fatalf("accepted %s", kind)
		}
	}
}

func TestLoadSessionRejectsMalformedAndUnknownDataSafely(t *testing.T) {
	const sentinel = "constructed-secret-that-must-not-be-logged"
	for _, input := range []string{
		`null`, `[]`, `{`, `{"username":"` + sentinel + `"}`,
		`{"username":"u","login_token":"t","authenticated_at":"2026-01-01T00:00:00Z","password":"` + sentinel + `"}`,
		`{"username":"u","login_token":"t","authenticated_at":"2026-01-01T00:00:00Z","nodes":[{"id":"1","signing_seed":"` + sentinel + `"}]}`,
		`{"username":"u","login_token":"t","nodes":[{"tcp_port":65536}]}`,
		`{"username":"u","login_token":"t","sync_version":{"bad&field":"1"}}`,
		`{"username":"u","login_token":"t"} {}`,
	} {
		directory := privateDirectory(t)
		if err := os.WriteFile(filepath.Join(directory, sessionFileName), []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadSession(directory)
		if err == nil || got.LoginToken != "" {
			t.Fatal("invalid session returned partial credentials")
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("session error exposed a parsed value")
		}
	}
}

func TestSessionSizeLimitIsSeparateFromProfileLimit(t *testing.T) {
	directory := privateDirectory(t)
	data, err := json.Marshal(publicSession())
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(strings.Repeat(" ", maxSessionBytes-len(data)))...)
	path := filepath.Join(directory, sessionFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(directory); err != nil {
		t.Fatalf("exact session limit rejected: %v", err)
	}
	if err := os.WriteFile(path, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(directory); err == nil {
		t.Fatal("oversize session accepted")
	}
	if maxPrivateFileBytes != 64<<10 {
		t.Fatal("profile size limit changed")
	}
}

func TestSaveSessionNodeLimitsPreserveExistingState(t *testing.T) {
	directory := privateDirectory(t)
	if err := SaveSession(directory, publicSession()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, sessionFileName)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*clientapi.Session){
		func(s *clientapi.Session) { s.Nodes = make([]clientapi.Node, maxStoredNodes+1) },
		func(s *clientapi.Session) { s.Nodes = []clientapi.Node{{UDPPort: -1}} },
		func(s *clientapi.Session) { s.Nodes = []clientapi.Node{{TCPPort: 65536}} },
		func(s *clientapi.Session) {
			s.Nodes = []clientapi.Node{{Title: strings.Repeat("x", maxNodeFieldBytes+1)}}
		},
		func(s *clientapi.Session) { s.SyncVersion = map[string]string{"bad]field": "1"} },
		func(s *clientapi.Session) {
			s.Nodes = make([]clientapi.Node, 300)
			for i := range s.Nodes {
				s.Nodes[i].Title = strings.Repeat("x", maxNodeFieldBytes)
			}
		},
	} {
		session := publicSession()
		change(&session)
		if err := SaveSession(directory, session); err == nil {
			t.Fatal("invalid or oversize public state accepted")
		}
		current, err := os.ReadFile(path)
		if err != nil || string(current) != string(original) {
			t.Fatal("failed save overwrote original state")
		}
		assertNoTemporaryFiles(t, directory)
	}
}

func TestLogoutSessionOnlyRemovesSessionAndRejectsLinks(t *testing.T) {
	directory := privateDirectory(t)
	if err := SaveSession(directory, publicSession()); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte("public profile sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LogoutSession(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directory, sessionFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("logout retained session")
	}
	if data, err := os.ReadFile(profilePath); err != nil || string(data) != "public profile sentinel" {
		t.Fatal("logout modified other files")
	}
	if err := LogoutSession(directory); err != nil {
		t.Fatal("missing session logout is not idempotent")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := LogoutSession(missing); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("logout created missing directory")
	}
	for _, kind := range []string{"symlink", "directory"} {
		badDir := privateDirectory(t)
		path := filepath.Join(badDir, sessionFileName)
		if kind == "symlink" {
			if err := os.Symlink(profilePath, path); err != nil {
				t.Skip("symbolic links unavailable")
			}
		} else if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := LogoutSession(badDir); err == nil {
			t.Fatalf("logout accepted %s", kind)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("logout removed rejected destination")
		}
	}
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := privatefile.MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeProfile(t *testing.T, profile clientapi.Profile, mode os.FileMode) string {
	t.Helper()
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDirectory(t), "profile.json")
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultDirectory(t *testing.T) {
	root, err := os.UserConfigDir()
	if err != nil {
		t.Skip("user configuration directory is unavailable")
	}
	got, err := DefaultDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "aijiasu-native"); got != want {
		t.Fatalf("DefaultDirectory() = %q, want %q", got, want)
	}
}

func TestLoadProfilePrivateModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix owner permission checks")
	}
	for _, mode := range []os.FileMode{0o400, 0o600} {
		t.Run(mode.String(), func(t *testing.T) {
			path := writeProfile(t, publicProfile(), mode)
			got, err := LoadProfile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Version != 1 || got.Endpoint != "https://example.test/client.php" || got.SigningSeed != "public-test-seed" {
				t.Fatal("profile fields did not survive private-file loading")
			}
		})
	}
}

func TestLoadProfileRejectsPublicPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix owner permission checks")
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o601, 0o200} {
		t.Run(mode.String(), func(t *testing.T) {
			path := writeProfile(t, publicProfile(), 0o600)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProfile(path); err == nil {
				t.Fatal("LoadProfile accepted unsafe permissions")
			}
		})
	}
}

func TestLoadProfileRejectsLinksAndDirectories(t *testing.T) {
	path := writeProfile(t, publicProfile(), 0o600)
	link := filepath.Join(t.TempDir(), "linked-profile.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symbolic links are unavailable")
	}
	for _, target := range []string{link, t.TempDir()} {
		if _, err := LoadProfile(target); err == nil {
			t.Fatal("LoadProfile accepted a symbolic link or directory")
		}
	}
}

func TestLoadProfileRejectsInvalidJSONWithoutValues(t *testing.T) {
	const privateSentinel = "test-only-value-that-must-not-appear-in-errors"
	inputs := []string{
		`{"version":`,
		`null`,
		`[]`,
		`{"version":"` + privateSentinel + `"}`,
		`{"` + privateSentinel + `":true}`,
	}
	valid, err := json.Marshal(publicProfile())
	if err != nil {
		t.Fatal(err)
	}
	inputs = append(inputs, string(valid)+` {}`, string(valid)+` trailing`)
	for _, input := range inputs {
		path := filepath.Join(privateDirectory(t), "profile.json")
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadProfile(path)
		if err == nil {
			t.Fatal("LoadProfile accepted invalid JSON")
		}
		if strings.Contains(err.Error(), privateSentinel) || strings.Contains(err.Error(), "public-test-seed") {
			t.Fatal("profile error disclosed a parsed value")
		}
		if got.SigningSeed != "" {
			t.Fatal("LoadProfile returned partial private fields with an error")
		}
	}
}

func TestLoadProfileValidatesRequiredFields(t *testing.T) {
	changes := []func(*clientapi.Profile){
		func(p *clientapi.Profile) { p.Version = 2 },
		func(p *clientapi.Profile) { p.Endpoint = "" },
		func(p *clientapi.Profile) { p.ClientVersion = "" },
		func(p *clientapi.Profile) { p.SigningSeed = "" },
	}
	for _, change := range changes {
		profile := publicProfile()
		change(&profile)
		if _, err := LoadProfile(writeProfile(t, profile, 0o600)); err == nil {
			t.Fatal("LoadProfile accepted an incomplete profile")
		}
	}
}

func TestLoadProfileSizeBoundary(t *testing.T) {
	data, err := json.Marshal(publicProfile())
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte(strings.Repeat(" ", maxPrivateFileBytes-len(data)))...)
	path := filepath.Join(privateDirectory(t), "profile.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err != nil {
		t.Fatalf("LoadProfile rejected the exact size limit: %v", err)
	}
	if err := os.WriteFile(path, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err == nil {
		t.Fatal("LoadProfile accepted a file over the size limit")
	}
}

func TestSaveSessionPrivateFieldsAndReplacement(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "new", "private")
	session := publicSession()
	if err := SaveSession(directory, session); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, sessionFileName)
	for _, target := range []struct {
		path string
		mode os.FileMode
	}{{directory, 0o700}, {path, 0o600}} {
		info, err := os.Stat(target.path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != target.mode {
			t.Fatalf("saved private path mode = %o, want %o", info.Mode().Perm(), target.mode)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 {
		t.Fatalf("saved session has %d fields, want only four", len(fields))
	}
	for _, key := range []string{"username", "login_token", "authenticated_at", "expire_time"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("saved session is missing field %s", key)
		}
	}
	for _, forbidden := range []string{"password", "signing_seed", "raw_response", "public-test-seed"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("saved session includes a field outside the allowlist")
		}
	}
	session.LoginToken = "replacement-public-token"
	session.ExpireTime = ""
	if err := SaveSession(directory, session); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "expire_time") || !strings.Contains(string(data), "replacement-public-token") {
		t.Fatal("session replacement or optional expiration serialization failed")
	}
	assertNoTemporaryFiles(t, directory)
}

func TestSaveSessionRejectsUnsafeDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix owner permission checks")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveSession(directory, publicSession()); err == nil {
		t.Fatal("SaveSession accepted a directory open to other users")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatal("SaveSession silently changed existing directory permissions")
	}
	assertNoTemporaryFiles(t, directory)
}

func TestSaveSessionRejectsSymbolicLinkDirectory(t *testing.T) {
	target := privateDirectory(t)
	link := filepath.Join(t.TempDir(), "private-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symbolic links are unavailable")
	}
	if err := SaveSession(link, publicSession()); err == nil {
		t.Fatal("SaveSession accepted a symbolic link directory")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("SaveSession wrote through a symbolic link directory")
	}
}

func TestSaveSessionRejectsNonregularDestination(t *testing.T) {
	for _, symbolicLink := range []bool{false, true} {
		directory := privateDirectory(t)
		path := filepath.Join(directory, sessionFileName)
		if symbolicLink {
			target := filepath.Join(t.TempDir(), "original.json")
			if err := os.WriteFile(target, []byte("original public content"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skip("symbolic links are unavailable")
			}
		} else if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := SaveSession(directory, publicSession()); err == nil {
			t.Fatal("SaveSession accepted a nonregular destination")
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if symbolicLink && info.Mode()&os.ModeSymlink == 0 || !symbolicLink && !info.IsDir() {
			t.Fatal("SaveSession replaced the rejected destination")
		}
		assertNoTemporaryFiles(t, directory)
	}
}

func TestSaveSessionValidationPreservesOriginal(t *testing.T) {
	directory := privateDirectory(t)
	path := filepath.Join(directory, sessionFileName)
	const original = "existing public session bytes"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	changes := []func(*clientapi.Session){
		func(s *clientapi.Session) { s.Username = "" },
		func(s *clientapi.Session) { s.LoginToken = " \n" },
		func(s *clientapi.Session) { s.LoginToken = strings.Repeat("a", maxSessionFieldBytes+1) },
		func(s *clientapi.Session) { s.ExpireTime = json.Number("test-only-private-invalid-number") },
	}
	for _, change := range changes {
		session := publicSession()
		change(&session)
		err := SaveSession(directory, session)
		if err == nil {
			t.Fatal("SaveSession accepted invalid session fields")
		}
		if strings.Contains(err.Error(), "test-only-private-invalid-number") {
			t.Fatal("session encoding error disclosed a field value")
		}
		assertOriginal(t, path, original)
		assertNoTemporaryFiles(t, directory)
	}
}

func TestPublicationFailurePreservesOriginalAndRemovesTemporaryFile(t *testing.T) {
	directory := privateDirectory(t)
	path := filepath.Join(directory, sessionFileName)
	const original = "existing public session bytes"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := openPrivateDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	publicationError := errors.New("injected publication failure")
	err = writeSession(root, []byte("new public session bytes"), func(old, new string) error {
		info, err := root.Lstat(old)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatal("temporary session file was not private")
		}
		return publicationError
	})
	if !errors.Is(err, publicationError) {
		t.Fatalf("publication failure lost its diagnostic context: %v", err)
	}
	assertOriginal(t, path, original)
	assertNoTemporaryFiles(t, directory)
}

func assertOriginal(t *testing.T, path, original string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatal("failed save changed the original session")
	}
}

func assertNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(directory, ".session-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatal("temporary session files were not removed")
	}
}
