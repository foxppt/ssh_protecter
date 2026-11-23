//go:build linux

package timeguard

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// Read-only adjtimex query: Modes=0 never changes the host clock.
func CheckSynchronized() error {
	var tx unix.Timex
	status, e := unix.Adjtimex(&tx)
	if e != nil {
		return e
	}
	if status == unix.TIME_ERROR || tx.Status&(unix.STA_UNSYNC|unix.STA_CLOCKERR) != 0 {
		return fmt.Errorf("kernel reports unsynchronized time; check chronyd/NTP")
	}
	return nil
}
