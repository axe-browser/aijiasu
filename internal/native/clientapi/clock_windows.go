package clientapi

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// DurationSinceBoot uses GetTickCount64, independent of wall-clock changes.
func MonotonicMilliseconds() (uint64, error) {
	elapsed := windows.DurationSinceBoot()
	if elapsed < 0 {
		return 0, errors.New("invalid monotonic clock value")
	}
	return uint64(elapsed / time.Millisecond), nil
}
