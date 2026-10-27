package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/privatefile"
)

func fixtureReference() []byte {
	values := map[uint64]string{
		seedAddress: "public-synthetic-initialization-seed", modulusAddress: "89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164812112068609",
		exponentAddress: "65537", coreVersionAddress: "20260525-1",
	}
	const start = modulusAddress
	const payload = seedAddress - start + maxStringBytes + 1
	data := make([]byte, 128+payload)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint32(data[64:], 1)
	binary.LittleEndian.PutUint32(data[68:], 4)
	binary.LittleEndian.PutUint64(data[72:], 128)
	binary.LittleEndian.PutUint64(data[80:], start)
	binary.LittleEndian.PutUint64(data[96:], payload)
	binary.LittleEndian.PutUint64(data[104:], payload)
	for address, value := range values {
		copy(data[128+address-start:], value)
	}
	return data
}

func fixtureDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func initializeFixture(ctx context.Context, directory string, pin string) (Result, error) {
	data := fixtureReference()
	return initialize(ctx, Options{Directory: directory, TLSPin: pin}, fixtureDigest(data),
		func(context.Context) ([]byte, error) { return append([]byte(nil), data...), nil }, (*os.Root).Link)
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := privatefile.MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func assertNoConfiguration(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{profileName, transportName} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected configuration file %s", name)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".init-") {
			t.Fatal("temporary initialization file was retained")
		}
	}
}

func TestInitializeCreatesPrivateUsableConfiguration(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	result, err := initializeFixture(t.Context(), directory, strings.Repeat("A", 64))
	if err != nil || !result.Initialized || strings.Join(result.Created, ",") != profileName+","+transportName || len(result.Preserved) != 0 {
		t.Fatalf("init result=%+v err=%v", result, err)
	}
	profile, err := authstore.LoadProfile(filepath.Join(directory, profileName))
	if err != nil || profile.TLSSPKISHA256 != strings.Repeat("a", 64) || len(profile.CommonParameters["_uid"]) != 22 || !strings.HasPrefix(profile.CommonParameters["_os_dim"], "lid=") {
		t.Fatal("new private profile is not usable")
	}
	if _, err := authstore.LoadTransportProfile(filepath.Join(directory, transportName)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{profileName, transportName} {
		filename := filepath.Join(directory, name)
		info, err := os.Stat(filename)
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 || privatefile.CheckPath(filename) != nil {
			t.Fatal("configuration is not private")
		}
	}
	info, err := os.Stat(directory)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 || privatefile.CheckPath(directory) != nil {
		t.Fatal("directory is not private")
	}
	other := filepath.Join(t.TempDir(), "other")
	if _, err := initializeFixture(t.Context(), other, ""); err != nil {
		t.Fatal(err)
	}
	second, _ := authstore.LoadProfile(filepath.Join(other, profileName))
	if second.CommonParameters["_uid"] == profile.CommonParameters["_uid"] || second.CommonParameters["_os_dim"] == profile.CommonParameters["_os_dim"] {
		t.Fatal("independent installation reused anonymous identifiers")
	}
}

func TestInitializePreservesExistingFilesAndDoesNotDownload(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if _, err := initializeFixture(t.Context(), directory, ""); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(directory, profileName))
	result, err := initialize(t.Context(), Options{Directory: directory, Reference: "/missing/offline/reference"}, "", func(context.Context) ([]byte, error) {
		t.Fatal("idempotent initialization downloaded a reference")
		return nil, nil
	}, (*os.Root).Link)
	after, _ := os.ReadFile(filepath.Join(directory, profileName))
	if err != nil || !result.Initialized || len(result.Created) != 0 || len(result.Preserved) != 2 || !bytes.Equal(before, after) {
		t.Fatalf("preservation failed: %+v %v", result, err)
	}
	if err := os.Remove(filepath.Join(directory, transportName)); err != nil {
		t.Fatal(err)
	}
	result, err = initializeFixture(t.Context(), directory, "")
	after, _ = os.ReadFile(filepath.Join(directory, profileName))
	if err != nil || len(result.Created) != 1 || result.Created[0] != transportName || len(result.Preserved) != 1 || !bytes.Equal(before, after) {
		t.Fatalf("partial preservation failed: %+v %v", result, err)
	}
}

func TestInitializeDoesNotOverwriteInvalidOrInsecureFiles(t *testing.T) {
	for _, kind := range []string{"invalid", "public", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "public" && runtime.GOOS == "windows" {
				t.Skip("Unix permission bits do not change Windows access control")
			}
			directory := privateDirectory(t)
			filename := filepath.Join(directory, profileName)
			switch kind {
			case "directory":
				if err := os.Mkdir(filename, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing", filename); err != nil {
					if runtime.GOOS == "windows" {
						t.Skip("Windows symbolic link creation requires developer mode or privilege")
					}
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filename, []byte("invalid-existing-preserved"), 0o600); err != nil {
					t.Fatal(err)
				}
				if kind == "public" {
					if err := os.Chmod(filename, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := initialize(t.Context(), Options{Directory: directory}, "", func(context.Context) ([]byte, error) {
				t.Fatal("invalid existing configuration triggered a download")
				return nil, nil
			}, (*os.Root).Link)
			if err == nil {
				t.Fatal("unsafe existing configuration was accepted")
			}
			if _, err := os.Lstat(filename); err != nil {
				t.Fatal("existing file was removed")
			}
		})
	}
	t.Run("public-directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Unix permission bits do not change Windows access control")
		}
		public := filepath.Join(t.TempDir(), "public")
		if err := os.Mkdir(public, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(public, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := initializeFixture(t.Context(), public, ""); err == nil {
			t.Fatal("public directory was accepted")
		}
		assertNoConfiguration(t, public)
	})
}

func TestInitializeExplicitPinCannotChangeExistingTrust(t *testing.T) {
	directory := privateDirectory(t)
	if _, err := initializeFixture(t.Context(), directory, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := initializeFixture(t.Context(), directory, strings.Repeat("A", 64)); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"malformed", strings.Repeat("b", 64)} {
		if _, err := initializeFixture(t.Context(), directory, pin); err == nil {
			t.Fatal("pin replacement was accepted")
		}
	}
	profile, _ := authstore.LoadProfile(filepath.Join(directory, profileName))
	if profile.TLSSPKISHA256 != strings.Repeat("a", 64) {
		t.Fatal("existing trust changed")
	}
	before, err := os.ReadFile(filepath.Join(directory, profileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializeFixture(t.Context(), directory, ""); err != nil {
		t.Fatal("default initialization rejected existing explicit trust")
	}
	after, err := os.ReadFile(filepath.Join(directory, profileName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("default initialization rewrote existing explicit trust")
	}
}

func TestInitializeConcurrentCallsPublishOnlyOnce(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	data := fixtureReference()
	var fetches atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			_, err := initialize(t.Context(), Options{Directory: directory}, fixtureDigest(data), func(context.Context) ([]byte, error) {
				fetches.Add(1)
				return append([]byte(nil), data...), nil
			}, (*os.Root).Link)
			if err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if fetches.Load() != 1 {
		t.Fatalf("concurrent initialization fetched %d times", fetches.Load())
	}
}

func TestInitializeCancellationAndFailedPublicationRollBack(t *testing.T) {
	for _, mode := range []string{"pre-canceled", "download", "second-publication", "between-publications"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "private")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			data := fixtureReference()
			if mode == "pre-canceled" {
				cancel()
			}
			calls := 0
			_, err := initialize(ctx, Options{Directory: directory}, fixtureDigest(data), func(context.Context) ([]byte, error) {
				if mode == "download" {
					cancel()
					return nil, ctx.Err()
				}
				return append([]byte(nil), data...), nil
			}, func(root *os.Root, source, target string) error {
				calls++
				if mode == "second-publication" && calls == 2 {
					return errors.New("synthetic publication failure")
				}
				err := root.Link(source, target)
				if mode == "between-publications" && calls == 1 {
					cancel()
				}
				return err
			})
			if err == nil {
				t.Fatal("failed initialization reported success")
			}
			assertNoConfiguration(t, directory)
		})
	}
}

func TestInitializeLockWaitCanBeCanceled(t *testing.T) {
	directory := privateDirectory(t)
	release, err := authstore.LockSessionLifecycleContext(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := initializeFixture(ctx, directory, ""); err == nil || ctx.Err() == nil {
		t.Fatal("lock wait ignored cancellation")
	}
	assertNoConfiguration(t, directory)
}

func TestInitializeReferenceIntegrityAndFileType(t *testing.T) {
	data := fixtureReference()
	reference := filepath.Join(t.TempDir(), "reference")
	if err := os.WriteFile(reference, data, 0o600); err != nil {
		t.Fatal(err)
	}
	options := Options{Directory: filepath.Join(t.TempDir(), "private"), Reference: reference}
	if _, err := initialize(t.Context(), options, referenceSHA256, nil, (*os.Root).Link); err == nil {
		t.Fatal("unknown reference hash was accepted")
	}
	assertNoConfiguration(t, options.Directory)
	if _, err := initialize(t.Context(), options, fixtureDigest(data), nil, (*os.Root).Link); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "reference-link")
	if err := os.Symlink(reference, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
	} else if _, err := readReference(t.Context(), link); err == nil {
		t.Fatal("reference symlink was accepted")
	}
	corrupt := append([]byte(nil), data...)
	corrupt[18] = 0
	if _, _, err := extractReference(corrupt, fixtureDigest(corrupt), ""); err == nil {
		t.Fatal("unsupported ELF architecture was accepted")
	}
	if _, err := boundedRead(t.Context(), bytes.NewReader([]byte("too-long")), 2); err == nil {
		t.Fatal("oversized reference read was accepted")
	}
}

type archiveEntry struct {
	name string
	kind byte
	data []byte
}

func fixtureArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Typeflag: entry.kind, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestDownloadReferenceDoesNotFollowRedirectsAndIsBounded(t *testing.T) {
	data := fixtureReference()
	archive := fixtureArchive(t, archiveEntry{"client/ajiasu", tar.TypeReg, data})
	var redirected atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() != "aijiasu-native/bootstrap-v1" {
			t.Error("download did not identify the native client")
		}
		switch request.URL.Path {
		case "/ok":
			writer.Write(archive)
		case "/redirect":
			http.Redirect(writer, request, "/target", http.StatusFound)
		case "/target":
			redirected.Add(1)
		case "/large":
			writer.Header().Set("Content-Length", fmt.Sprint(maxArchiveBytes+1))
			writer.WriteHeader(http.StatusOK)
		case "/bad":
			writer.Write([]byte("not-gzip"))
		default:
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	got, err := downloadReference(t.Context(), client, server.URL+"/ok")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("reference download did not extract the executable")
	}
	for _, route := range []string{"/redirect", "/large", "/bad", "/unavailable"} {
		if _, err := downloadReference(t.Context(), client, server.URL+route); err == nil {
			t.Fatalf("invalid download accepted: %s", route)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("download followed a redirect")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := downloadReference(ctx, client, server.URL+"/ok"); !errors.Is(err, context.Canceled) {
		t.Fatal("download ignored cancellation")
	}
}

func TestExtractArchiveRejectsDuplicateMissingAndNonregularReferences(t *testing.T) {
	for _, entries := range [][]archiveEntry{
		{{"ajiasu", tar.TypeReg, []byte("one")}, {"elsewhere/ajiasu", tar.TypeReg, []byte("two")}},
		{{"readme", tar.TypeReg, []byte("text")}},
		{{"ajiasu", tar.TypeSymlink, nil}},
	} {
		if _, err := extractArchive(t.Context(), fixtureArchive(t, entries...)); err == nil {
			t.Fatal("invalid reference archive was accepted")
		}
	}
	if _, err := boundedRead(t.Context(), io.LimitReader(strings.NewReader("long"), 4), 3); err == nil {
		t.Fatal("chunked oversized input was accepted")
	}
}
