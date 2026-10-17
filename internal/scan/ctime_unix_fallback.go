//go:build unix && !linux && !darwin && !freebsd

package scan

import "os"

// ctime is unavailable on this unix; read-time consistency falls back to
// size/mtime/inode comparison.
func ctime(fi os.FileInfo) int64 { return 0 }
