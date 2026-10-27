//go:build darwin || linux || windows

package authstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"aijiasu-native/internal/native/clientapi"
	"aijiasu-native/internal/native/privatefile"
)

func TestFirstPasswordLoginCommitsWithoutAnExistingSession(t *testing.T) {
	directory := filepath.Join(privateDirectory(t), "new-installation")
	version, err := BeginLogin(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capturing a password login created a session")
	}
	want := publicSession()
	if err := SaveLoginSession(directory, version, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSession(directory)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("first password login did not preserve its session")
	}
	info, err := os.Stat(filepath.Join(directory, sessionLockName))
	if err != nil || !privatefile.PrivateMode(info, true) || privatefile.CheckPath(filepath.Join(directory, sessionLockName)) != nil || info.Size() != sessionRevisionBytes {
		t.Fatal("login revision was not kept in the private bounded lock file")
	}
	if err := SaveLoginSession(directory, version, want); !errors.Is(err, ErrSessionChanged) {
		t.Fatal("password response could be committed more than once")
	}
	assertNoTemporaryFiles(t, directory)
}

func TestPasswordLoginRejectsLogoutWithOrWithoutAnExistingSession(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, coordinated := range []bool{false, true} {
			t.Run(fmt.Sprintf("existing=%v/coordinated=%v", existing, coordinated), func(t *testing.T) {
				directory := privateDirectory(t)
				if existing {
					if err := SaveSession(directory, publicSession()); err != nil {
						t.Fatal(err)
					}
				}
				version, err := BeginLogin(directory)
				if err != nil {
					t.Fatal(err)
				}
				if coordinated {
					stopped := false
					err = LogoutSessionAfterStop(directory, func() error { stopped = true; return nil })
					if !stopped {
						t.Fatal("logout skipped the worker stop operation")
					}
				} else {
					err = LogoutSession(directory)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := SaveLoginSession(directory, version, publicSession()); !errors.Is(err, ErrSessionChanged) {
					t.Fatal("a pending password response undid logout")
				}
				if _, err := LoadSession(directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("logout retained or recreated a session")
				}
				fresh, err := BeginLogin(directory)
				if err != nil {
					t.Fatal(err)
				}
				if err := SaveLoginSession(directory, fresh, publicSession()); err != nil {
					t.Fatal("a new login could not succeed after logout")
				}
			})
		}
	}
}

func TestPasswordLoginRejectsAnotherSavedLoginOrRefresh(t *testing.T) {
	for _, change := range []string{"unconditional-login", "password-login", "refresh"} {
		t.Run(change, func(t *testing.T) {
			directory := privateDirectory(t)
			original := publicSession()
			if err := SaveSession(directory, original); err != nil {
				t.Fatal(err)
			}
			pending, err := BeginLogin(directory)
			if err != nil {
				t.Fatal(err)
			}
			winning := original
			winning.LoginToken = "winning-public-token"
			switch change {
			case "unconditional-login":
				// Even identical session contents represent a distinct publication.
				winning = original
				err = SaveSession(directory, winning)
			case "password-login":
				var other LoginVersion
				other, err = BeginLogin(directory)
				if err == nil {
					err = SaveLoginSession(directory, other, winning)
				}
			case "refresh":
				var refresh SessionVersion
				refresh, err = VersionOfSession(directory, original)
				if err == nil {
					err = SaveRefreshedSession(directory, refresh, winning)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			stale := original
			stale.LoginToken = "stale-password-public-token"
			if err := SaveLoginSession(directory, pending, stale); !errors.Is(err, ErrSessionChanged) {
				t.Fatal("password response overwrote a newer committed session")
			}
			got, err := LoadSession(directory)
			if err != nil || !reflect.DeepEqual(got, winning) {
				t.Fatal("the winning session changed")
			}
		})
	}
}

func TestConcurrentPasswordLoginsOnlyCommitTheFirstResult(t *testing.T) {
	directory := privateDirectory(t)
	version, err := BeginLogin(directory)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		session clientapi.Session
		err     error
	}
	const attempts = 8
	results := make(chan result, attempts)
	start := make(chan struct{})
	for index := range attempts {
		go func() {
			<-start
			session := publicSession()
			session.Username = fmt.Sprintf("public-account-%d", index)
			results <- result{session, SaveLoginSession(directory, version, session)}
		}()
	}
	close(start)
	var winner clientapi.Session
	committed := 0
	for range attempts {
		result := <-results
		if result.err == nil {
			committed++
			winner = result.session
		} else if !errors.Is(result.err, ErrSessionChanged) {
			t.Fatalf("concurrent password login failed unexpectedly: %v", result.err)
		}
	}
	got, err := LoadSession(directory)
	if committed != 1 || err != nil || !reflect.DeepEqual(got, winner) {
		t.Fatal("concurrent password logins did not retain exactly one winner")
	}
}

func TestPasswordLoginRejectsReplacedDirectoryAndLock(t *testing.T) {
	for _, replaced := range []string{"directory", "lock", "empty-version"} {
		t.Run(replaced, func(t *testing.T) {
			directory := filepath.Join(privateDirectory(t), "installation")
			version, err := BeginLogin(directory)
			if err != nil {
				t.Fatal(err)
			}
			switch replaced {
			case "directory":
				if err := os.Rename(directory, directory+"-old"); err != nil {
					t.Fatal(err)
				}
				if _, err := BeginLogin(directory); err != nil {
					t.Fatal(err)
				}
			case "lock":
				path := filepath.Join(directory, sessionLockName)
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "empty-version":
				version = LoginVersion{}
			}
			if err := SaveLoginSession(directory, version, publicSession()); !errors.Is(err, ErrSessionChanged) {
				t.Fatal("password login accepted a replaced version identity")
			}
			if _, err := LoadSession(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected password login still created a session")
			}
		})
	}
}

func TestFailedWorkerStopPreservesSessionAndPendingLogin(t *testing.T) {
	directory := privateDirectory(t)
	want := publicSession()
	if err := SaveSession(directory, want); err != nil {
		t.Fatal(err)
	}
	pending, err := BeginLogin(directory)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("public worker stop failure")
	if err := LogoutSessionAfterStop(directory, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal("logout did not preserve the worker stop error")
	}
	got, err := LoadSession(directory)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("failed worker stop removed or changed the session")
	}
	if err := SaveLoginSession(directory, pending, want); err != nil {
		t.Fatal("failed worker stop invalidated pending login state")
	}
	if err := LogoutSessionAfterStop(directory, nil); err == nil {
		t.Fatal("logout accepted a missing worker stop operation")
	}
}

const lifecycleProcessDirectory = "AIJIASU_PUBLIC_LIFECYCLE_TEST_DIRECTORY"

func TestSessionLifecycleProcessHelper(t *testing.T) {
	directory := os.Getenv(lifecycleProcessDirectory)
	if directory == "" {
		return
	}
	fmt.Println("waiting")
	if err := LogoutSessionAfterStop(directory, func() error {
		fmt.Println("stopping")
		var signal string
		if _, err := fmt.Fscanln(os.Stdin, &signal); err != nil || signal != "finish" {
			return errors.New("missing public lifecycle test signal")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleLockSerializesWorkerRegistrationAndOtherProcessLogout(t *testing.T) {
	directory := privateDirectory(t)
	if err := SaveSession(directory, publicSession()); err != nil {
		t.Fatal(err)
	}
	release, err := LockSessionLifecycle(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSessionLifecycleProcessHelper$")
	command.Env = append(os.Environ(), lifecycleProcessDirectory+"="+directory)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "waiting" {
		t.Fatal("child did not start its logout")
	}
	stopping := make(chan bool, 1)
	go func() { stopping <- scanner.Scan() && scanner.Text() == "stopping" }()
	select {
	case <-stopping:
		t.Fatal("logout bypassed the worker registration lock")
	case <-time.After(100 * time.Millisecond):
	}
	var releases sync.WaitGroup
	for range 8 {
		releases.Go(release)
	}
	releases.Wait()
	if !<-stopping {
		t.Fatal("child did not stop the worker after registration released its lock")
	}
	type lockResult struct {
		release func()
		err     error
	}
	registered := make(chan lockResult, 1)
	go func() {
		unlock, err := LockSessionLifecycle(directory)
		registered <- lockResult{unlock, err}
	}()
	select {
	case result := <-registered:
		if result.release != nil {
			result.release()
		}
		t.Fatal("new worker registration bypassed the in-progress logout")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := fmt.Fprintln(stdin, "finish"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("child logout failed: %v", err)
	}
	result := <-registered
	if result.err != nil {
		t.Fatal(result.err)
	}
	result.release()
	result.release()
	if _, err := LoadSession(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new registration observed a session after completed logout")
	}
}
