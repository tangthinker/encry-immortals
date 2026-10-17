//go:build !unix

package scan

import "os"

func sysInfo(fi os.FileInfo) (ino, dev, nlink uint64, blocks int64, ok bool) {
	return 0, 0, 0, 0, false
}

func ctime(fi os.FileInfo) int64 { return 0 }
