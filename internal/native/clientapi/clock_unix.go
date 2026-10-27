//go:build darwin || linux

package clientapi

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// MonotonicMilliseconds uses the clock observed in the Linux 4.3.0.1 client.
func MonotonicMilliseconds() (uint64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0, fmt.Errorf("read monotonic clock: %w", err)
	}
	if value.Sec < 0 || value.Nsec < 0 || value.Nsec >= 1_000_000_000 {
		return 0, errors.New("invalid monotonic clock value")
	}
	seconds, milliseconds := uint64(value.Sec), uint64(value.Nsec)/1_000_000
	if seconds > (^uint64(0)-milliseconds)/1_000 {
		return 0, errors.New("monotonic clock value overflows milliseconds")
	}
	return seconds*1_000 + milliseconds, nil
}
