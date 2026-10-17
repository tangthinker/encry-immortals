//go:build !linux && !darwin

package scan

// hasXattrs is unavailable on this platform; the check is skipped (documented
// in README's known limitations).
func hasXattrs(path string) (bool, []string, error) { return false, nil, nil }
