//go:build unix

package scan

import (
	"os"
	"syscall"
)

func sysInfo(fi os.FileInfo) (ino, dev, nlink uint64, blocks int64, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, 0, 0, false
	}
	return uint64(st.Ino), uint64(st.Dev), uint64(st.Nlink), int64(st.Blocks), true
}

func ctime(fi os.FileInfo) int64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ctimespec.Nano() + st.Ctimespec.Sec*1e9
}
