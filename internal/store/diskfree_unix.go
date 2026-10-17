//go:build unix

package store

import "syscall"

// DiskFree reports the bytes available to the current user on the filesystem
// holding path (spec 11.4: compact must check free space before writing).
func DiskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
