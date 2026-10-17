package vaultcrypto

import "runtime"

// SecureKey is a best-effort protected key buffer.
//
// Go's runtime cannot guarantee that no copy of a key ever reaches the heap, so
// this type does what is achievable: page-lock the buffer where the OS allows it
// and wipe it deterministically on Destroy (spec §02.11).
type SecureKey struct {
	b      []byte
	locked bool
}

// NewSecureKey allocates a zeroed, page-locked (where supported) buffer.
func NewSecureKey(size int) *SecureKey {
	b := make([]byte, size)
	return &SecureKey{b: b, locked: lockMemory(b)}
}

// SecureKeyFromBytes wraps an existing buffer. The caller must not retain b.
func SecureKeyFromBytes(b []byte) *SecureKey {
	return &SecureKey{b: b, locked: lockMemory(b)}
}

// Bytes exposes the key material. Never log or copy it.
func (k *SecureKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	return k.b
}

// Len reports the key length in bytes.
func (k *SecureKey) Len() int {
	if k == nil {
		return 0
	}
	return len(k.b)
}

// Locked reports whether the buffer was successfully page-locked.
func (k *SecureKey) Locked() bool {
	if k == nil {
		return false
	}
	return k.locked
}

// Destroy zeroes the buffer, unlocks it and drops the reference. It is safe to
// call more than once.
func (k *SecureKey) Destroy() {
	if k == nil || k.b == nil {
		return
	}
	Zero(k.b)
	if k.locked {
		unlockMemory(k.b)
	}
	k.locked = false
	k.b = nil
}

// Zero overwrites b with zeros and keeps it alive across the loop so the
// compiler cannot elide the writes.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
