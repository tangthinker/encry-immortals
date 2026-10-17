//go:build !unix

package vaultcrypto

// lockMemory is a no-op on platforms without mlock support in syscall.
func lockMemory(b []byte) bool { return false }

func unlockMemory(b []byte) {}
