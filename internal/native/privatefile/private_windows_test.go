package privatefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateWindowsSecurityDescriptors(t *testing.T) {
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	owner := "O:" + user.String()
	for _, test := range []struct {
		name  string
		sddl  string
		valid bool
	}{
		{"current-user", owner + "D:P(A;;FA;;;" + user.String() + ")", true},
		{"privileged-system", owner + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.String() + ")", true},
		{"deny-others", owner + "D:P(D;;FA;;;WD)(A;;FA;;;" + user.String() + ")", true},
		{"world-read", owner + "D:P(A;;FR;;;WD)(A;;FA;;;" + user.String() + ")", false},
		{"authenticated-users", owner + "D:P(A;;FR;;;AU)(A;;FA;;;" + user.String() + ")", false},
		{"world-inherited-children", owner + "D:P(A;OICIIO;FA;;;WD)(A;;FA;;;" + user.String() + ")", false},
		{"untrusted-owner", "O:WDD:P(A;;FA;;;" + user.String() + ")", false},
		{"null-dacl", owner + "D:NO_ACCESS_CONTROL", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal("cannot construct public security descriptor fixture")
			}
			if got := checkDescriptor(descriptor, user) == nil; got != test.valid {
				t.Fatal("private security descriptor acceptance mismatch")
			}
		})
	}
}

func TestPrivateWindowsCreationAndExistingACLRejection(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private", "nested")
	if err := MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	if err := CheckPath(directory); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := CheckRoot(root); err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile("private.json", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := CheckFile(file); err != nil {
		t.Fatal("new file did not inherit private permissions")
	}
	path := filepath.Join(directory, "private.json")
	setWorldReadableACL(t, path)
	if CheckPath(path) == nil || CheckFile(file) == nil {
		t.Fatal("broad file permissions accepted")
	}
	setWorldReadableACL(t, directory)
	if err := MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	if CheckPath(directory) == nil || CheckRoot(root) == nil {
		t.Fatal("existing broad directory was accepted or silently changed")
	}
}

func setWorldReadableACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal("cannot set fixture DACL")
	}
}
