// Package vaultcrypto implements APEX's key hierarchy (spec docs/spec/02-crypto.md).
//
// Chain: password --Argon2id(salt, t, m, p)--> MasterKey
//
//	--HKDF-SHA256(salt=vault_id, info=*)--> {Storage, Journal, Path, Anchor}
//
// Invariants enforced here:
//   - I18: nonces only ever come from the CSPRNG (see RandomNonce).
//   - I19: KDF parameters are frozen after init; callers may only read them.
//   - Every derivation domain is an explicit, versioned HKDF info string.
package vaultcrypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Wire constants shared with the storage layer (spec §02.5, §03.3).
const (
	// WireVersion is the high nibble of every ver_alg byte.
	WireVersion = 1
	// AlgXChaCha20Poly1305 is the low nibble of ver_alg.
	AlgXChaCha20Poly1305 = 1
	// VerAlg is 0x11 for v1: wire version 1, algorithm 1.
	VerAlg byte = WireVersion<<4 | AlgXChaCha20Poly1305
)

// Sizes fixed by the spec. They are intentionally constants: any change is a
// wire-format change and must bump WireVersion.
const (
	KeyLen     = 32
	SaltLen    = 16
	VaultIDLen = 16
	NonceLen   = 24
	TagLen     = 16
)

// KDF parameter bounds (spec §02.7). The lower memory bound is a hard reject,
// never a warning: parameters are frozen for the lifetime of a vault.
const (
	KDFAlgArgon2id = "argon2id"

	KDFTimeMin    uint32 = 3
	KDFTimeMax    uint32 = 8
	KDFThreadsMax uint8  = 4

	KDFMemoryKiBMin     uint32 = 131072  // 128 MiB
	KDFMemoryKiBMax     uint32 = 1048576 // 1 GiB
	KDFMemoryKiBDefault uint32 = 262144  // 256 MiB
)

// HKDF info strings (spec §02.2). Must stay byte-identical across versions.
const (
	HKDFInfoStorage = "apex-storage-payload-v2"
	HKDFInfoJournal = "apex-journal-manifest-v2"
	HKDFInfoPath    = "apex-path-hmac-v2"
	HKDFInfoAnchor  = "apex-anchor-v2"
)

// DefaultThreads is min(4, NumCPU) per spec §02.7.
func DefaultThreads() uint8 {
	n := runtime.NumCPU()
	if n > int(KDFThreadsMax) {
		n = int(KDFThreadsMax)
	}
	if n < 1 {
		n = 1
	}
	return uint8(n)
}

// KDFParams are the Argon2id parameters recorded in vault.meta and frozen at
// init time. They are never recalibrated or overridden afterwards (I19).
type KDFParams struct {
	Algorithm        string
	Time             uint32
	MemoryKiB        uint32
	Threads          uint8
	KeyLen           uint32
	Salt             []byte
	CalibratedAtUnix int64
}

// Validate enforces the spec's hard bounds. It must be called on every read of
// vault.meta and on every init attempt.
func (p KDFParams) Validate() error {
	if p.Algorithm != KDFAlgArgon2id {
		return fmt.Errorf("kdf: unsupported algorithm %q", p.Algorithm)
	}
	if len(p.Salt) != SaltLen {
		return fmt.Errorf("kdf: salt must be %d bytes, got %d", SaltLen, len(p.Salt))
	}
	if p.Time < KDFTimeMin || p.Time > KDFTimeMax {
		return fmt.Errorf("kdf: time %d outside [%d,%d]", p.Time, KDFTimeMin, KDFTimeMax)
	}
	if p.MemoryKiB < KDFMemoryKiBMin || p.MemoryKiB > KDFMemoryKiBMax {
		return fmt.Errorf("kdf: memory %d KiB outside [%d,%d]", p.MemoryKiB, KDFMemoryKiBMin, KDFMemoryKiBMax)
	}
	if p.Threads < 1 || p.Threads > KDFThreadsMax {
		return fmt.Errorf("kdf: threads %d outside [1,%d]", p.Threads, KDFThreadsMax)
	}
	if p.KeyLen != KeyLen {
		return fmt.Errorf("kdf: keylen must be %d, got %d", KeyLen, p.KeyLen)
	}
	return nil
}

// CanonBlock is the fixed-format ASCII block hashed into the auth_verifier AAD
// (spec §02.4): argon2id|t=<time>|m=<memory_kiB>|p=<threads>|k=<keylen>|salt=<Base64URL>.
// It must never be produced by a generic JSON serialiser.
func (p KDFParams) CanonBlock() string {
	var b strings.Builder
	b.WriteString(p.Algorithm)
	b.WriteString("|t=")
	b.WriteString(strconvU(p.Time))
	b.WriteString("|m=")
	b.WriteString(strconvU(p.MemoryKiB))
	b.WriteString("|p=")
	b.WriteString(strconvU(uint32(p.Threads)))
	b.WriteString("|k=")
	b.WriteString(strconvU(p.KeyLen))
	b.WriteString("|salt=")
	b.WriteString(base64.RawURLEncoding.EncodeToString(p.Salt))
	return b.String()
}

// strconvU formats unsigned integers without importing strconv at every call site.
func strconvU(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

// DeriveMasterKey runs Argon2id over the master password.
//
// The result stays in memory only; callers must Destroy it.
func DeriveMasterKey(password []byte, p KDFParams) (*SecureKey, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b := argon2.IDKey(password, p.Salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return SecureKeyFromBytes(b), nil
}

// Subkeys holds the four domain-separated child keys of spec §02.2.
type Subkeys struct {
	Storage *SecureKey
	Journal *SecureKey
	Path    *SecureKey
	Anchor  *SecureKey
}

// Destroy wipes and unlocks every subkey.
func (s *Subkeys) Destroy() {
	if s == nil {
		return
	}
	s.Storage.Destroy()
	s.Journal.Destroy()
	s.Path.Destroy()
	s.Anchor.Destroy()
}

// DeriveSubkeys expands the MasterKey into the four child keys, using vault_id
// as HKDF salt so two vaults with the same password never share keys.
func DeriveSubkeys(master, vaultID []byte) (*Subkeys, error) {
	if len(master) != KeyLen {
		return nil, fmt.Errorf("kdf: master key must be %d bytes, got %d", KeyLen, len(master))
	}
	if len(vaultID) != VaultIDLen {
		return nil, fmt.Errorf("kdf: vault_id must be %d bytes, got %d", VaultIDLen, len(vaultID))
	}
	out := &Subkeys{}
	for _, d := range []struct {
		dst  **SecureKey
		info string
	}{
		{&out.Storage, HKDFInfoStorage},
		{&out.Journal, HKDFInfoJournal},
		{&out.Path, HKDFInfoPath},
		{&out.Anchor, HKDFInfoAnchor},
	} {
		k, err := hkdf.Key(sha256.New, master, vaultID, d.info, KeyLen)
		if err != nil {
			out.Destroy()
			return nil, fmt.Errorf("kdf: hkdf %s: %w", d.info, err)
		}
		*d.dst = SecureKeyFromBytes(k)
	}
	return out, nil
}
