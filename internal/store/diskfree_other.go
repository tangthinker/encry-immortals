//go:build !unix

package store

// DiskFree is unknown on this platform; callers treat 0 as "cannot tell" and
// rely on the write itself failing loudly.
func DiskFree(path string) (int64, error) { return 0, nil }
