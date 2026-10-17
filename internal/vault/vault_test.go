package vault

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
)

func minParams(t *testing.T) vaultcrypto.KDFParams {
	t.Helper()
	return vaultcrypto.KDFParams{
		Algorithm: vaultcrypto.KDFAlgArgon2id,
		Time:      vaultcrypto.KDFTimeMin,
		MemoryKiB: vaultcrypto.KDFMemoryKiBMin,
		Threads:   4,
		KeyLen:    vaultcrypto.KeyLen,
		Salt:      bytes.Repeat([]byte{0x5a}, vaultcrypto.SaltLen),
	}
}

func testMeta(t *testing.T) *Meta {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	return &Meta{
		Version:     MetaVersion,
		VaultID:     b64(bytes.Repeat([]byte{1}, 16)),
		CreatedUnix: 1773000000,
		KDF: KDFJSON{
			Algorithm: "argon2id", Time: 3, MemoryKiB: 131072, Threads: 4, KeyLen: 32,
			Salt: b64(bytes.Repeat([]byte{2}, 16)), CalibratedAtUnix: 1773000000,
		},
		AuthVerifier: VerifierJSON{
			Algorithm:  "xchacha20poly1305",
			Nonce:      b64(bytes.Repeat([]byte{3}, vaultcrypto.NonceLen)),
			Ciphertext: b64(bytes.Repeat([]byte{4}, len(vaultcrypto.VerifierPlaintext)+vaultcrypto.TagLen)),
		},
	}
}

func TestNewMetaAndUnlock(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2id at the spec lower bound takes ~1s per derivation")
	}
	params := minParams(t)
	password := []byte("test-password-123456")
	m, err := NewMeta(password, params, time.Unix(1773000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != MetaVersion || m.VaultID == "" {
		t.Fatalf("unexpected meta: %+v", m)
	}
	keys, err := m.Unlock(password)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if len(keys.Sub.Journal.Bytes()) != vaultcrypto.KeyLen {
		t.Fatal("journal key not derived")
	}
	keys.Destroy()

	// Wrong password and tampered parameters must be indistinguishable.
	if _, err := m.Unlock([]byte("wrong-password")); err == nil {
		t.Fatal("wrong password accepted")
	} else if apexerr.CodeOf(err) != apexerr.CodeUnlock {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeUnlock)
	}
	tampered := *m
	tampered.KDF = m.KDF
	tampered.KDF.MemoryKiB = 262144
	if _, err := tampered.Unlock(password); err == nil {
		t.Fatal("tampered KDF parameters were accepted")
	}
}

func TestMetaSaveLoadAndPermissions(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2id at the spec lower bound takes ~1s")
	}
	dir := t.TempDir()
	params := minParams(t)
	m, err := NewMeta([]byte("test-password-123456"), params, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Save(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != FilePerm {
		t.Fatalf("vault.meta mode = %o, want %o", info.Mode().Perm(), FilePerm)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != DirPerm {
		t.Fatalf("control plane mode = %o, want %o", dirInfo.Mode().Perm(), DirPerm)
	}
	loaded, err := LoadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.VaultID != m.VaultID || loaded.KDF.MemoryKiB != m.KDF.MemoryKiB {
		t.Fatalf("load mismatch: %+v vs %+v", loaded, m)
	}
}

func TestLoadMetaMissingIsUsageError(t *testing.T) {
	_, err := LoadMeta(t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a missing vault.meta")
	}
	if apexerr.CodeOf(err) != apexerr.CodeUsage {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeUsage)
	}
}

func TestParseMetaRejectsInvalid(t *testing.T) {
	valid := testMeta(t)
	if _, err := ParseMeta(mustJSON(t, valid)); err != nil {
		t.Fatalf("valid meta rejected: %v", err)
	}
	mutate := func(f func(*Meta)) []byte {
		m := testMeta(t)
		f(m)
		return mustJSON(t, m)
	}
	cases := map[string][]byte{
		"version 3":     mutate(func(m *Meta) { m.Version = 3 }),
		"bad salt":      mutate(func(m *Meta) { m.KDF.Salt = base64.RawURLEncoding.EncodeToString([]byte{1, 2}) }),
		"bad base64":    mutate(func(m *Meta) { m.KDF.Salt = "!!!" }),
		"low memory":    mutate(func(m *Meta) { m.KDF.MemoryKiB = 65536 }),
		"bad algorithm": mutate(func(m *Meta) { m.KDF.Algorithm = "scrypt" }),
		"short nonce":   mutate(func(m *Meta) { m.AuthVerifier.Nonce = base64.RawURLEncoding.EncodeToString([]byte{1}) }),
		"short ct":      mutate(func(m *Meta) { m.AuthVerifier.Ciphertext = base64.RawURLEncoding.EncodeToString([]byte{1}) }),
		"bad verifier":  mutate(func(m *Meta) { m.AuthVerifier.Algorithm = "aes-gcm" }),
		"short vault id": mutate(func(m *Meta) {
			m.VaultID = base64.RawURLEncoding.EncodeToString([]byte{1})
		}),
		"not json": []byte("not json"),
	}
	for name, raw := range cases {
		if _, err := ParseMeta(raw); err == nil {
			t.Errorf("%s: expected a rejection", name)
		}
	}
}

func mustJSON(t *testing.T, m *Meta) []byte {
	t.Helper()
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCalibrateDecisionTable(t *testing.T) {
	salt := bytes.Repeat([]byte{9}, vaultcrypto.SaltLen)
	now := time.Unix(1773000000, 0)
	ok := func(p vaultcrypto.KDFParams) time.Duration { return 1500 * time.Millisecond }
	p, err := Calibrate(salt, 4, ok, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.MemoryKiB != vaultcrypto.KDFMemoryKiBDefault {
		t.Fatalf("in-range probe should keep 256 MiB, got %d", p.MemoryKiB)
	}

	// Fast: double until it is slow enough.
	p, err = Calibrate(salt, 4, func(p vaultcrypto.KDFParams) time.Duration {
		if p.MemoryKiB < 524288 {
			return 500 * time.Millisecond
		}
		return 1500 * time.Millisecond
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.MemoryKiB != 524288 {
		t.Fatalf("fast probe should double to 512 MiB, got %d", p.MemoryKiB)
	}

	// Always too slow: fall back to the hard lower bound.
	p, err = Calibrate(salt, 4, func(p vaultcrypto.KDFParams) time.Duration {
		return 3000 * time.Millisecond
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.MemoryKiB != vaultcrypto.KDFMemoryKiBMin {
		t.Fatalf("slow probe should fall back to %d KiB, got %d", vaultcrypto.KDFMemoryKiBMin, p.MemoryKiB)
	}

	// Always instant: cap at 1 GiB.
	p, err = Calibrate(salt, 4, func(p vaultcrypto.KDFParams) time.Duration {
		return 1 * time.Millisecond
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.MemoryKiB != vaultcrypto.KDFMemoryKiBMax {
		t.Fatalf("instant probe should cap at %d KiB, got %d", vaultcrypto.KDFMemoryKiBMax, p.MemoryKiB)
	}
}

func TestCheckPassword(t *testing.T) {
	weak := []string{"", "abc", "password", "123456789012", "aaaaaaaaaaaaaa", "qwerty", "letmein"}
	for _, pw := range weak {
		if s := CheckPassword([]byte(pw)); !s.RequiresConfirmation() {
			t.Errorf("CheckPassword(%q) = level %d %v, want weak", pw, s.Level, s.Reasons)
		}
	}
	good := []string{
		"correct horse battery staple",
		"Tr0ub4dor&3-plus-extra",
		"9f2!kQ#vL8@xD1$zP4^m",
	}
	for _, pw := range good {
		if s := CheckPassword([]byte(pw)); s.RequiresConfirmation() {
			t.Errorf("CheckPassword(%q) = weak %v, want acceptable", pw, s.Reasons)
		}
	}
}

func TestArmorRoundTrip(t *testing.T) {
	m := testMeta(t)
	armored, err := m.Armor()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(armored, "APEX-KEY-V2-") {
		t.Fatalf("armor prefix missing: %q", armored[:20])
	}
	back, err := ParseArmorString(armored)
	if err != nil {
		t.Fatal(err)
	}
	if back.VaultID != m.VaultID || back.KDF.Salt != m.KDF.Salt {
		t.Fatal("armor round trip mismatch")
	}
	corrupted := armored[:len(armored)-1] + "Q"
	if _, err := ParseArmorString(corrupted); err == nil {
		t.Fatal("expected a corrupted armor string to be rejected")
	} else if apexerr.CodeOf(err) != apexerr.CodeArmor {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeArmor)
	}
}

func TestInitWritesControlPlane(t *testing.T) {
	dir := t.TempDir()
	res, err := Init(dir, InitOptions{
		Password:    []byte("weak"),
		Threads:     4,
		Now:         time.Unix(1773000000, 0),
		ToolVersion: "test",
	})
	if err == nil {
		t.Fatalf("weak password should need confirmation, got %+v", res)
	} else if apexerr.CodeOf(err) != apexerr.CodeUsage {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeUsage)
	}

	res, err = Init(dir, InitOptions{
		Password:    []byte("weak-but-accepted"),
		Threads:     4,
		Now:         time.Unix(1773000000, 0),
		Probe:       func(p vaultcrypto.KDFParams) time.Duration { return 1500 * time.Millisecond },
		Force:       true,
		ToolVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Params.MemoryKiB != vaultcrypto.KDFMemoryKiBDefault {
		t.Fatalf("params memory = %d", res.Params.MemoryKiB)
	}
	for _, name := range []string{MetaFileName, RecoveryFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, RecoveryFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"主密码不可更改", res.Meta.VaultID, "apex export-key"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("RECOVERY.txt is missing %q", want)
		}
	}
	loaded, err := LoadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.VaultID != res.Meta.VaultID {
		t.Fatal("saved vault.meta does not match")
	}
}
