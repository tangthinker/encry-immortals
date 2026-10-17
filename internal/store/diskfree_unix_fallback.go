//go:build unix && !linux && !darwin && !freebsd

package store

// DiskFree is unknown on this unix flavour; callers treat 0 as "cannot tell".
func DiskFree(path string) (int64, error) { return 0, nil }
