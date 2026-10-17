//go:build linux

package lock

import (
	"os"
	"strings"
)

// readBootID returns the kernel boot id, used to spot stale locks.
func readBootID() string {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
