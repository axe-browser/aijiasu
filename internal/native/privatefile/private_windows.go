package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows permission bits only describe the read-only attribute. Every caller
// must also check the actual object DACL with CheckPath, CheckRoot or CheckFile.
func PrivateMode(info os.FileInfo, _ bool) bool { return info != nil }

// MkdirAll creates new directories with a protected DACL before they become
// visible. Existing directories are not modified and must be checked separately.
func MkdirAll(path string) error {
	if path == "" {
		return errors.New("private directory path is required")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() {
			return errors.New("private directory path is not a directory")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect private directory")
	}
	parent := filepath.Dir(path)
	if parent == path {
		return errors.New("cannot locate private directory parent")
	}
	if err := MkdirAll(parent); err != nil {
		return err
	}
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner.String() + "D:P(A;OICI;FA;;;" + owner.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return errors.New("cannot construct private directory permissions")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("invalid private directory path")
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := windows.CreateDirectory(name, &attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.New("cannot create private directory")
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return nil, errors.New("cannot identify private configuration owner")
	}
	return user.User.Sid.Copy()
}

// CheckPath opens the named entry itself, rather than following a reparse point.
// Object types (including an AF_UNIX socket reparse point) remain caller-checked.
func CheckPath(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("invalid private object path")
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("cannot inspect private object permissions")
	}
	defer windows.CloseHandle(handle)
	return checkHandle(handle)
}

func CheckRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return errors.New("cannot inspect private directory permissions")
	}
	defer file.Close()
	return CheckFile(file)
}

func CheckFile(file *os.File) error {
	if file == nil {
		return errors.New("private file handle is required")
	}
	return checkHandle(windows.Handle(file.Fd()))
}

func checkHandle(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("cannot read private object permissions")
	}
	owner, err := currentUserSID()
	if err != nil {
		return err
	}
	return checkDescriptor(descriptor, owner)
}

func trustedSID(sid, user *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func checkDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if descriptor == nil || !descriptor.IsValid() || user == nil || !user.IsValid() {
		return errors.New("invalid private object permissions")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !trustedSID(owner, user) {
		return errors.New("private object has an untrusted owner")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("private object requires a restrictive DACL")
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("cannot inspect private object DACL")
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart))+8 {
				return errors.New("invalid private object access entry")
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trustedSID(sid, user) {
				return errors.New("private object grants access to other users")
			}
		default:
			return errors.New("unsupported private object access entry")
		}
	}
	return nil
}
