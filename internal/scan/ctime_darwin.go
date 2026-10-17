//go:build darwin

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
	return st.Ctimespec.Nano() + st.Ctimespec.Sec*1e9
}
