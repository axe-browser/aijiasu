// Package bootstrap prepares private protocol configuration from one pinned
// reference build. The reference is inspected as data and is never executed.
package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"aijiasu-native/internal/native/authstore"
	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/privatefile"
)

const (
	referenceURL       = "https://www.91ajs.com/files/downloads/linux/ajiasu-amd64-4.3.0.1.tar.gz"
	referenceSHA256    = "08fcd8668f7aaf6660277778e67fd2afd622c3f1c8fb634e57f31605bf01c8f6"
	maxReferenceBytes  = 8 << 20
	maxArchiveBytes    = 16 << 20
	maxArchiveEntries  = 128
	maxExtractedBytes  = 32 << 20
	maxStringBytes     = 4096
	downloadTimeout    = 45 * time.Second
	seedAddress        = 0x693080
	modulusAddress     = 0x68f548
	exponentAddress    = 0x68f67e
	coreVersionAddress = 0x692860
	profileName        = "compatibility.json"
	transportName      = "transport.json"
)

var (
	ErrDownload      = errors.New("cannot download the pinned reference")
	ErrReference     = errors.New("reference integrity or format is invalid")
	ErrConfiguration = errors.New("private initialization storage is invalid")
	ErrTLSConflict   = errors.New("existing login TLS pin differs")
)

// Options never contains account credentials. TLSPin must be independently
// trusted by the caller; initialization never observes or accepts a login pin.
type Options struct {
	Directory string
	Reference string
	TLSPin    string
}

// Result is the public init JSON contract. Only configuration filenames appear;
// private values and user-specific filesystem paths are never returned.
type Result struct {
	Initialized bool     `json:"initialized"`
	Created     []string `json:"created"`
	Preserved   []string `json:"preserved"`
}

// Initialize preserves valid existing configuration and publishes only missing
// files. Every file is complete before exclusive publication; failed publication
// rolls back this call's files. After a process crash a later init fills any gap.
func Initialize(ctx context.Context, options Options) (Result, error) {
	return initialize(ctx, options, referenceSHA256, fetchReference, (*os.Root).Link)
}

type fetchFunc func(context.Context) ([]byte, error)
type linkFunc func(*os.Root, string, string) error

func initialize(ctx context.Context, options Options, digest string, fetch fetchFunc, link linkFunc) (result Result, resultErr error) {
	result = Result{Created: []string{}, Preserved: []string{}}
	if ctx == nil || options.Directory == "" {
		return result, errors.New("initialization requires a context and private directory")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	pin := strings.ToLower(options.TLSPin)
	if pin != "" {
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != sha256.Size {
			return result, errors.New("login TLS pin must be a SHA-256 hexadecimal digest")
		}
	}
	release, err := authstore.LockSessionLifecycleContext(ctx, options.Directory)
	if err != nil {
		return result, errors.Join(ErrConfiguration, errors.New("cannot lock private initialization directory"))
	}
	defer release()
	root, err := os.OpenRoot(options.Directory)
	if err != nil {
		return result, errors.Join(ErrConfiguration, errors.New("cannot open private initialization directory"))
	}
	defer root.Close()
	if err := verifyDirectory(root, options.Directory); err != nil {
		return result, errors.Join(ErrConfiguration, err)
	}
	missing := []string{}
	for _, name := range []string{profileName, transportName} {
		_, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, name)
			continue
		}
		if err != nil {
			return result, errors.Join(ErrConfiguration, errors.New("cannot inspect existing private configuration"))
		}
		if name == profileName {
			profile, err := authstore.LoadProfile(filepath.Join(options.Directory, name))
			if err != nil {
				return result, errors.Join(ErrConfiguration, errors.New("existing compatibility configuration is invalid or not private"))
			}
			if _, err := clientapi.NewClient(clientapi.Config{Endpoint: profile.Endpoint, SigningSeed: profile.SigningSeed,
				CommonParameters: profile.CommonParameters, TLSSPKISHA256: profile.TLSSPKISHA256}); err != nil {
				return result, errors.Join(ErrConfiguration, errors.New("existing compatibility configuration is invalid"))
			}
			if pin != "" && !strings.EqualFold(pin, profile.TLSSPKISHA256) {
				return result, ErrTLSConflict
			}
		} else if _, err := authstore.LoadTransportProfile(filepath.Join(options.Directory, name)); err != nil {
			return result, errors.Join(ErrConfiguration, errors.New("existing transport configuration is invalid or not private"))
		}
		result.Preserved = append(result.Preserved, name)
	}
	if len(missing) == 0 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.Initialized = true
		return result, nil
	}
	var reference []byte
	if options.Reference != "" {
		reference, err = readReference(ctx, options.Reference)
		if err != nil {
			return result, errors.Join(ErrReference, err)
		}
	} else {
		reference, err = fetch(ctx)
		if err != nil {
			return result, errors.Join(ErrDownload, err)
		}
	}
	defer clear(reference)
	profile, transport, err := extractReference(reference, digest, pin)
	if err != nil {
		return result, errors.Join(ErrReference, err)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	staged := make(map[string]string, len(missing))
	defer func() {
		for _, name := range staged {
			if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, ErrConfiguration, errors.New("cannot remove staged private configuration"))
			}
		}
	}()
	for _, name := range missing {
		var value any = profile
		if name == transportName {
			value = transport
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return result, errors.New("cannot encode private configuration")
		}
		temporary, err := stageFile(ctx, root, append(data, '\n'))
		clear(data)
		if err != nil {
			return result, errors.Join(ErrConfiguration, err)
		}
		staged[name] = temporary
	}
	if err := verifyDirectory(root, options.Directory); err != nil {
		return result, errors.Join(ErrConfiguration, err)
	}
	created := []string{}
	rollback := func() error {
		var rollbackErr error
		for _, name := range created {
			original, firstErr := root.Lstat(staged[name])
			current, secondErr := root.Lstat(name)
			if firstErr == nil && secondErr == nil && os.SameFile(original, current) {
				if err := root.Remove(name); err != nil {
					rollbackErr = errors.Join(ErrConfiguration, errors.New("cannot roll back newly published configuration"))
				}
			} else if firstErr != nil || secondErr != nil && !errors.Is(secondErr, os.ErrNotExist) {
				rollbackErr = errors.Join(ErrConfiguration, errors.New("cannot inspect newly published configuration for rollback"))
			}
		}
		return rollbackErr
	}
	for _, name := range missing {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(err, rollback())
		}
		if err := link(root, staged[name], name); err != nil {
			return result, errors.Join(ErrConfiguration, errors.New("cannot exclusively publish private configuration"), rollback())
		}
		created = append(created, name)
	}
	result.Initialized = true
	result.Created = created
	return result, nil
}

func verifyDirectory(root *os.Root, directory string) error {
	opened, firstErr := root.Stat(".")
	current, secondErr := os.Lstat(directory)
	if firstErr != nil || secondErr != nil || !current.IsDir() || !privatefile.PrivateMode(current, false) || !os.SameFile(opened, current) {
		return errors.New("initialization directory changed or is not private")
	}
	if err := privatefile.CheckRoot(root); err != nil {
		return errors.New("initialization directory access permissions are not private")
	}
	return nil
}

func stageFile(ctx context.Context, root *os.Root, data []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	name := ".init-" + rand.Text() + ".tmp"
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("cannot stage private configuration")
	}
	if err := privatefile.CheckFile(file); err != nil {
		return "", errors.Join(errors.New("staged configuration access permissions are not private"), file.Close(), root.Remove(name))
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || ctx.Err() != nil {
		_ = root.Remove(name)
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return "", errors.New("cannot finish staging private configuration")
	}
	return name, nil
}

func readReference(ctx context.Context, filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReferenceBytes {
		return nil, errors.New("reference must be a bounded regular file without a symbolic link")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("cannot open reference file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("reference file changed while opening")
	}
	return boundedRead(ctx, file, maxReferenceBytes)
}

func boundedRead(ctx context.Context, reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		clear(data)
		return nil, errors.New("reference exceeds its size limit or cannot be read")
	}
	if err := ctx.Err(); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

func fetchReference(ctx context.Context) ([]byte, error) {
	client := &http.Client{Timeout: downloadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return downloadReference(ctx, client, referenceURL)
}

func downloadReference(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("cannot prepare reference download")
	}
	request.Header.Set("User-Agent", "aijiasu-native/bootstrap-v1")
	request.Header.Set("Accept", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("reference download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxArchiveBytes {
		return nil, errors.New("reference download returned an unexpected status or size")
	}
	compressed, err := boundedRead(ctx, response.Body, maxArchiveBytes)
	if err != nil {
		return nil, err
	}
	defer clear(compressed)
	return extractArchive(ctx, compressed)
}

func extractArchive(ctx context.Context, compressed []byte) ([]byte, error) {
	stream, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, errors.New("reference archive is not valid gzip")
	}
	defer stream.Close()
	archive := tar.NewReader(io.LimitReader(stream, maxExtractedBytes+1))
	var reference []byte
	var total int64
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			clear(reference)
			return nil, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || entries >= maxArchiveEntries || header.Size < 0 || header.Size > maxExtractedBytes-total {
			clear(reference)
			return nil, errors.New("reference archive exceeds limits or is invalid")
		}
		total += header.Size
		if path.Base(header.Name) != "ajiasu" {
			continue
		}
		if reference != nil || header.Typeflag != tar.TypeReg || header.Size > maxReferenceBytes {
			clear(reference)
			return nil, errors.New("reference archive has an invalid or duplicate executable")
		}
		reference, err = boundedRead(ctx, archive, maxReferenceBytes)
		if err != nil {
			return nil, err
		}
	}
	if len(reference) == 0 {
		return nil, errors.New("reference archive does not contain the expected executable")
	}
	return reference, nil
}

func extractReference(data []byte, expected, pin string) (clientapi.Profile, authstore.TransportProfile, error) {
	var profile clientapi.Profile
	var transport authstore.TransportProfile
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return profile, transport, errors.New("reference SHA-256 does not match the supported build")
	}
	binary, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Machine != elf.EM_X86_64 {
		return profile, transport, errors.New("reference ELF format is unsupported")
	}
	defer binary.Close()
	values := make([]string, 4)
	for index, address := range []uint64{seedAddress, modulusAddress, exponentAddress, coreVersionAddress} {
		values[index], err = referenceString(binary, address)
		if err != nil {
			return profile, transport, err
		}
	}
	transport = authstore.TransportProfile{Version: 1, CoreVersion: values[3], Modulus: values[1], Exponent: values[2]}
	if _, err := transport.PublicKey(); err != nil || transport.Exponent != "65537" || transport.CoreVersion != "20260525-1" {
		return profile, transport, errors.New("reference transport metadata is invalid")
	}
	profile, err = newProfile(values[0], pin)
	return profile, transport, err
}

func referenceString(binary *elf.File, address uint64) (string, error) {
	for _, program := range binary.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr || address-program.Vaddr >= program.Filesz {
			continue
		}
		offset := address - program.Vaddr
		data, err := io.ReadAll(io.NewSectionReader(program, int64(offset), int64(min(program.Filesz-offset, maxStringBytes+1))))
		if err != nil {
			return "", errors.New("cannot inspect reference protocol metadata")
		}
		end := bytes.IndexByte(data, 0)
		if end <= 0 || end > maxStringBytes || !utf8.Valid(data[:end]) {
			return "", errors.New("reference protocol metadata is invalid")
		}
		return string(data[:end]), nil
	}
	return "", errors.New("reference protocol metadata mapping is missing")
}

func newProfile(seed, pin string) (clientapi.Profile, error) {
	milliseconds, err := clientapi.MonotonicMilliseconds()
	if err != nil {
		return clientapi.Profile{}, errors.New("cannot prepare anonymous installation identifier")
	}
	random := make([]byte, 20)
	if _, err := rand.Read(random); err != nil {
		return clientapi.Profile{}, errors.New("cannot prepare anonymous installation identifier")
	}
	uid := fmt.Sprintf("%08x%02x%s", uint32(milliseconds/1000), byte(milliseconds), hex.EncodeToString(random[:4]))
	a, b := uint32(0xdeadbeef), uint32(0xcafebabe)
	for _, value := range []byte(uid) {
		a ^= (a << 5) + uint32(value) + (a >> 2)
		b = uint32(value) + (b << 6) + (b << 16) - b
	}
	uid += fmt.Sprintf("%02x%02x", byte(a>>24), byte(b>>24))
	return clientapi.Profile{Version: 1, Endpoint: "https://login.ajs-app.com/client.php", ClientVersion: "4.3.0.1",
		SigningSeed: seed, TLSSPKISHA256: pin, CommonParameters: map[string]string{
			"v": "4.3.0.1", "_site": "ajs", "_lang": "en", "_m": "linux", "_os_ver": runtime.GOOS,
			"_os_dev": runtime.GOARCH, "_os_dim": "lid=" + hex.EncodeToString(random[4:]), "_uid": uid,
		}}, nil
}
