//go:build !linux

package lock

// readBootID is not available on this platform; the field stays empty and the
// operator judges staleness from host/pid/started_unix.
func readBootID() string { return "" }
