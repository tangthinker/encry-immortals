//go:build unix

package store

import (
	"os"
	"syscall"
)

// sameVolume compares st_dev of two existing directories (§01.2).
func sameVolume(a, b string) (bool, error) {
	sa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	da, okA := sa.Sys().(*syscall.Stat_t)
	db, okB := sb.Sys().(*syscall.Stat_t)
	if !okA || !okB {
		return false, nil
	}
	return da.Dev == db.Dev, nil
}
