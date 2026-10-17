//go:build linux

package scan

import (
	"os"
	"syscall"
)

func ctime(fi os.FileInfo) int64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ctim.Nano() + st.Ctim.Sec*1e9
}
