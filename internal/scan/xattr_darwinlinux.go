//go:build linux || darwin

package scan

import (
	"strings"

	"golang.org/x/sys/unix"
)

// hasXattrs reports whether path carries extended attributes, without following
// symlinks (spec 01.6: xattr/ACL are not restored, so their presence must be a
// deliberate opt-in).
func hasXattrs(path string) (bool, []string, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		if err == unix.ENOTSUP || err == unix.EOPNOTSUPP {
			return false, nil, nil
		}
		return false, nil, err
	}
	if size <= 0 {
		return false, nil, nil
	}
	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return false, nil, err
	}
	raw := strings.Split(strings.TrimRight(string(buf[:n]), "\x00"), "\x00")
	names := make([]string, 0, len(raw))
	for _, name := range raw {
		if name != "" {
			names = append(names, name)
		}
	}
	return len(names) > 0, names, nil
}
