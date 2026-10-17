//go:build linux || darwin

package vaultcrypto

import "syscall"

func lockMemory(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return syscall.Mlock(b) == nil
}

func unlockMemory(b []byte) {
	if len(b) > 0 {
		_ = syscall.Munlock(b)
	}
}
