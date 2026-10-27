//go:build !darwin && !linux && !windows

package clientapi

import "errors"

func MonotonicMilliseconds() (uint64, error) {
	return 0, errors.New("monotonic login clock is unsupported on this platform")
}
