//go:build !windows

// Package privatefile supplies the platform-specific permission checks used by
// private configuration stores. Callers still validate object type and identity.
package privatefile

import "os"

func MkdirAll(path string) error { return os.MkdirAll(path, 0o700) }

// PrivateMode checks Unix permission bits; Windows callers separately validate
// the object's DACL through CheckPath, CheckRoot or CheckFile.
func PrivateMode(info os.FileInfo, requireRead bool) bool {
	return info != nil && info.Mode().Perm()&0o077 == 0 && (!requireRead || info.Mode().Perm()&0o400 != 0)
}

func CheckPath(string) error   { return nil }
func CheckRoot(*os.Root) error { return nil }
func CheckFile(*os.File) error { return nil }
