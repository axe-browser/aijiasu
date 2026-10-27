package bootstrap

import (
	"os"
	"path/filepath"
	"testing"

	"aijiasu-native/internal/native/privatefile"
	"golang.org/x/sys/windows"
)

func TestWindowsInitializationRejectsPublicACLBeforeWriting(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "public-acl")
	if err := privatefile.MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;GR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := verifyDirectory(root, directory); err == nil {
		t.Fatal("readable-by-everyone initialization directory was accepted")
	}
	if _, err := stageFile(t.Context(), root, []byte("public-placeholder-not-to-be-written")); err == nil {
		t.Fatal("configuration was staged with a readable-by-everyone DACL")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected configuration left a staging file")
	}
}
