package main

import (
	"path/filepath"
	"testing"

	"aijiasu-native/internal/native/privatefile"
)

func privateCLIStateDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := privatefile.MkdirAll(directory); err != nil {
		t.Fatal(err)
	}
	if err := privatefile.CheckPath(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}
