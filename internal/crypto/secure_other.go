//go:build !linux && !darwin

package vaultcrypto

// lockMemory is unavailable here (syscall.Mlock is not portable to every
// platform); keys still get deterministic zeroisation via SecureKey.Destroy.
func lockMemory(b []byte) bool { return false }

func unlockMemory(b []byte) {}
