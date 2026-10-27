//go:build !darwin && !linux && !windows

package main

import (
	"context"
	"errors"
)

func readTerminalPassword(context.Context) ([]byte, error) {
	return nil, errors.New("interactive password input is supported on macOS, Linux and Windows; use password-stdin on this platform")
}
