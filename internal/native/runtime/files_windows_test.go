package runtime

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aijiasu-native/internal/native/fvproxy"
	"aijiasu-native/internal/native/privatefile"

	"golang.org/x/sys/windows"
)

func TestWindowsRuntimeLockAcrossProcesses(t *testing.T) {
	config := testConfig(t)
	directory, err := openRuntimeDirectory(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if directory != nil {
			directory.close()
		}
	})
	runHelper := func(expect string) {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestWindowsRuntimeLockProcessHelper$")
		command.Env = append(os.Environ(), "AIJIASU_RUNTIME_LOCK_HELPER="+expect, "AIJIASU_RUNTIME_LOCK_DIRECTORY="+config.Directory)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cross-process runtime lock failed: %v; %s", err, output)
		}
	}
	runHelper("locked")
	directory.close()
	directory = nil
	runHelper("available")
}

func TestWindowsRuntimeLockProcessHelper(t *testing.T) {
	expect := os.Getenv("AIJIASU_RUNTIME_LOCK_HELPER")
	if expect == "" {
		return
	}
	directory, err := openRuntimeDirectory(os.Getenv("AIJIASU_RUNTIME_LOCK_DIRECTORY"))
	if directory != nil {
		directory.close()
	}
	if expect == "locked" && err == nil || expect == "available" && err != nil {
		t.Fatal("runtime lock did not enforce cross-process ownership")
	}
}

func TestWindowsRuntimeDialErrorsAndStaleSocket(t *testing.T) {
	for _, test := range []struct {
		cause      error
		notRunning bool
	}{
		{windows.WSAECONNREFUSED, true},
		{windows.ERROR_FILE_NOT_FOUND, true},
		{windows.WSAEACCES, false},
		{windows.WSAEINVAL, false},
		{windows.WSAENOBUFS, false},
	} {
		cause := &net.OpError{Op: "dial", Net: "unix", Err: test.cause}
		if err := runtimeDialFailure(context.Background(), cause); errors.Is(err, ErrNotRunning) != test.notRunning {
			t.Fatal("Windows control failure was misclassified")
		}
	}
	config := testConfig(t)
	directory, err := openRuntimeDirectory(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := directory.bindSocket()
	if err != nil {
		directory.close()
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		directory.close()
		t.Fatal(err)
	}
	if _, err := Call(context.Background(), config.Directory, Request{Command: "status"}); !errors.Is(err, ErrNotRunning) {
		directory.close()
		t.Fatalf("stale AF_UNIX socket was not classified as stopped: %v", err)
	}
	directory.close()
}

func TestWindowsRuntimeRefusesBroadControlSocketACL(t *testing.T) {
	config := testConfig(t)
	_, cancel, done := startRuntime(t, config, testDeps(func(fvproxy.Config) (proxyEngine, error) { return &fakeEngine{}, nil }))
	defer func() { cancel(); _ = await(t, done) }()
	path := filepath.Join(config.Directory, socketName)
	if err := privatefile.CheckPath(path); err != nil {
		t.Fatal("created AF_UNIX socket is not private")
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	_, err = Call(context.Background(), config.Directory, Request{Command: "status"})
	if err == nil || errors.Is(err, ErrNotRunning) || strings.Contains(err.Error(), path) {
		t.Fatal("broad control ACL was accepted, misclassified or disclosed")
	}
}
