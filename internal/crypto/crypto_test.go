package vaultcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestVerAlgIs0x11(t *testing.T) {
	if VerAlg != 0x11 {
		t.Fatalf("VerAlg = %#x, want 0x11 (wire version 1, XChaCha20-Poly1305)", VerAlg)
	}
}

func TestAADLayouts(t *testing.T) {
	packID := bytes.Repeat([]byte{0xAA}, 16)
	txnID := bytes.Repeat([]byte{0xBB}, 16)
	vaultID := bytes.Repeat([]byte{0xCC}, 16)

	got, err := SliceAAD(VerAlg, 1, 100, 80, packID, 7, 3, txnID)
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	want = append(want, 0x11, 0, 0, 0, 100, 0, 0, 0, 80)
	want = append(want, packID...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 7)
	want = append(want, 0, 0, 0, 3)
	want = append(want, txnID...)
	want = append(want, 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("SliceAAD = %x\nwant        %x", got, want)
	}
	if len(got) != SliceAADLen {
		t.Fatalf("SliceAAD length = %d, want %d", len(got), SliceAADLen)
	}

	got, err = JournalAAD(VerAlg, 0, 42, vaultID)
	if err != nil {
		t.Fatal(err)
	}
	want = append([]byte{0x11, 0}, 0, 0, 0, 0, 0, 0, 0, 42)
	want = append(want, vaultID...)
	if !bytes.Equal(got, want) {
		t.Fatalf("JournalAAD = %x\nwant          %x", got, want)
	}
	if len(got) != JournalAADLen {
		t.Fatalf("JournalAAD length = %d, want %d", len(got), JournalAADLen)
	}

	got, err = FooterAAD(VerAlg, packID, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want = append([]byte{0x11}, packID...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0x10, 0x00)
	if !bytes.Equal(got, want) {
		t.Fatalf("FooterAAD = %x\nwant         %x", got, want)
	}
	if len(got) != FooterAADLen {
		t.Fatalf("FooterAAD length = %d, want %d", len(got), FooterAADLen)
	}

	canon := "argon2id|t=3|m=262144|p=4|k=32|salt=AAAA"
	got, err = VerifierAAD(VerAlg, vaultID, canon)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canon))
	want = append([]byte{0x11}, vaultID...)
	want = append(want, sum[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("VerifierAAD mismatch")
	}
	if len(got) != VerifierAADLen {
		t.Fatalf("VerifierAAD length = %d, want %d", len(got), VerifierAADLen)
	}
}

func TestAADRejectsBadIDLengths(t *testing.T) {
	if _, err := SliceAAD(VerAlg, 0, 1, 1, make([]byte, 15), 0, 0, make([]byte, 16)); err == nil {
		t.Fatal("expected an error for a 15-byte pack_id")
	}
	if _, err := SliceAAD(VerAlg, 0, 1, 1, make([]byte, 16), 0, 0, make([]byte, 17)); err == nil {
		t.Fatal("expected an error for a 17-byte txn_id")
	}
	if _, err := JournalAAD(VerAlg, 0, 1, make([]byte, 8)); err == nil {
		t.Fatal("expected an error for a short vault_id")
	}
	if _, err := VerifierAAD(VerAlg, make([]byte, 8), "x"); err == nil {
		t.Fatal("expected an error for a short vault_id")
	}
}

func TestKDFParamsValidate(t *testing.T) {
	valid := KDFParams{
		Algorithm: KDFAlgArgon2id, Time: 3, MemoryKiB: KDFMemoryKiBMin, Threads: 4,
		KeyLen: KeyLen, Salt: make([]byte, SaltLen),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	mutate := func(f func(*KDFParams)) KDFParams {
		p := valid
		p.Salt = append([]byte(nil), valid.Salt...)
		f(&p)
		return p
	}
	cases := map[string]KDFParams{
		"algorithm":  mutate(func(p *KDFParams) { p.Algorithm = "scrypt" }),
		"short salt": mutate(func(p *KDFParams) { p.Salt = p.Salt[:8] }),
		"time low":   mutate(func(p *KDFParams) { p.Time = 2 }),
		"time high":  mutate(func(p *KDFParams) { p.Time = 9 }),
		"mem low":    mutate(func(p *KDFParams) { p.MemoryKiB = 65536 }),
		"mem high":   mutate(func(p *KDFParams) { p.MemoryKiB = 2 << 20 }),
		"threads 0":  mutate(func(p *KDFParams) { p.Threads = 0 }),
		"threads 5":  mutate(func(p *KDFParams) { p.Threads = 5 }),
		"keylen":     mutate(func(p *KDFParams) { p.KeyLen = 16 }),
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestCanonKDFBlockFormat(t *testing.T) {
	p := KDFParams{
		Algorithm: KDFAlgArgon2id, Time: 3, MemoryKiB: 262144, Threads: 4, KeyLen: 32,
		Salt: []byte{0, 1, 2, 3},
	}
	want := "argon2id|t=3|m=262144|p=4|k=32|salt=AAECAw"
	if got := p.CanonBlock(); got != want {
		t.Fatalf("CanonBlock = %q, want %q", got, want)
	}
}

// refHKDF is an independent RFC 5869 HKDF-SHA256 (extract + expand).
func refHKDF(ikm, salt []byte, info string, n int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)
	var out, t []byte
	for counter := byte(1); len(out) < n; counter++ {
		h = hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write([]byte(info))
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func TestDeriveSubkeysMatchesReferenceAndIsDomainSeparated(t *testing.T) {
	master := make([]byte, KeyLen)
	for i := range master {
		master[i] = byte(i)
	}
	vaultID := bytes.Repeat([]byte{0x5a}, VaultIDLen)

	sk, err := DeriveSubkeys(master, vaultID)
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Destroy()

	for _, c := range []struct {
		name string
		got  []byte
		info string
	}{
		{"storage", sk.Storage.Bytes(), HKDFInfoStorage},
		{"journal", sk.Journal.Bytes(), HKDFInfoJournal},
		{"path", sk.Path.Bytes(), HKDFInfoPath},
		{"anchor", sk.Anchor.Bytes(), HKDFInfoAnchor},
	} {
		if len(c.got) != KeyLen {
			t.Fatalf("%s: length %d", c.name, len(c.got))
		}
		want := refHKDF(master, vaultID, c.info, KeyLen)
		if !bytes.Equal(c.got, want) {
			t.Fatalf("%s subkey mismatch\ngot  %x\nwant %x", c.name, c.got, want)
		}
	}
	if bytes.Equal(sk.Storage.Bytes(), sk.Journal.Bytes()) {
		t.Fatal("storage and journal keys must differ")
	}

	other, err := DeriveSubkeys(master, bytes.Repeat([]byte{0x5b}, VaultIDLen))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	if bytes.Equal(sk.Storage.Bytes(), other.Storage.Bytes()) {
		t.Fatal("vault_id must participate in derivation")
	}
}

func TestDeriveMasterKeyMatchesArgon2(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2id at the spec lower bound takes ~1s")
	}
	p := KDFParams{
		Algorithm: KDFAlgArgon2id, Time: KDFTimeMin, MemoryKiB: KDFMemoryKiBMin,
		Threads: 4, KeyLen: KeyLen, Salt: bytes.Repeat([]byte{7}, SaltLen),
	}
	password := []byte("correct horse battery staple")
	sk, err := DeriveMasterKey(password, p)
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Destroy()
	want := argon2.IDKey(password, p.Salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	if !bytes.Equal(sk.Bytes(), want) {
		t.Fatal("DeriveMasterKey does not match argon2.IDKey")
	}

	// Below the hard lower bound must be rejected, not warned about.
	weak := p
	weak.MemoryKiB = 65536
	if _, err := DeriveMasterKey(password, weak); err == nil {
		t.Fatal("expected the KDF lower bound to be enforced")
	}
	if !sk.Locked() {
		t.Log("note: mlock unavailable in this environment")
	}
}

func TestVerifierSealOpen(t *testing.T) {
	journalKey, err := RandomBytes(KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	vaultID, err := RandomBytes(VaultIDLen)
	if err != nil {
		t.Fatal(err)
	}
	canon := "argon2id|t=3|m=262144|p=4|k=32|salt=AAECAw"
	nonce, ct, err := SealAuthVerifier(journalKey, vaultID, canon)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != NonceLen || len(ct) != len(VerifierPlaintext)+TagLen {
		t.Fatalf("nonce %d ct %d", len(nonce), len(ct))
	}
	if err := OpenAuthVerifier(journalKey, nonce, ct, vaultID, canon); err != nil {
		t.Fatalf("open: %v", err)
	}

	otherKey := append([]byte(nil), journalKey...)
	otherKey[0] ^= 0xff
	if err := OpenAuthVerifier(otherKey, nonce, ct, vaultID, canon); err == nil {
		t.Fatal("wrong key must fail")
	}
	if err := OpenAuthVerifier(journalKey, nonce, ct, vaultID, canon+" "); err == nil {
		t.Fatal("tampered kdf block must fail")
	}
	otherVault := append([]byte(nil), vaultID...)
	otherVault[0] ^= 0xff
	if err := OpenAuthVerifier(journalKey, nonce, ct, otherVault, canon); err == nil {
		t.Fatal("wrong vault_id must fail")
	}
	if err := OpenAuthVerifier(journalKey, nonce, ct[:len(ct)-1], vaultID, canon); err == nil {
		t.Fatal("truncated ciphertext must fail")
	}
	bad := append([]byte(nil), ct...)
	bad[3] ^= 0x01
	if err := OpenAuthVerifier(journalKey, nonce, bad, vaultID, canon); err == nil {
		t.Fatal("flipped ciphertext must fail")
	}
}

func TestSecureKeyDestroyZeroes(t *testing.T) {
	k := NewSecureKey(32)
	for i := range k.Bytes() {
		k.Bytes()[i] = 0xee
	}
	k.Destroy()
	if k.Bytes() != nil {
		t.Fatal("Destroy must release the buffer")
	}
	buf := bytes.Repeat([]byte{0xff}, 16)
	Zero(buf)
	if !bytes.Equal(buf, make([]byte, 16)) {
		t.Fatal("Zero must wipe the buffer")
	}
	k.Destroy() // idempotent
}

func TestNonceUniqueness(t *testing.T) {
	const n = 20000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		nonce, err := RandomNonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != NonceLen {
			t.Fatalf("nonce length %d", len(nonce))
		}
		if _, dup := seen[string(nonce)]; dup {
			t.Fatal("nonce collision")
		}
		seen[string(nonce)] = struct{}{}
	}
}

func TestPathHMACAndAnchorMAC(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeyLen)
	a := PathHMAC(key, []byte("photos/2026/a.jpg"))
	b := PathHMAC(key, []byte("photos/2026/a.jpg"))
	if a != b {
		t.Fatal("PathHMAC must be deterministic")
	}
	if a == PathHMAC(key, []byte("photos/2026/b.jpg")) {
		t.Fatal("different paths must hash differently")
	}
	otherKey := bytes.Repeat([]byte{2}, KeyLen)
	if PathHMAC(otherKey, []byte("photos/2026/a.jpg")) == a {
		t.Fatal("PathHMAC must be keyed")
	}

	sha := sha256.Sum256([]byte("journal"))
	m1 := AnchorMAC(key, 1, sha)
	if m1 == AnchorMAC(key, 2, sha) {
		t.Fatal("anchor MAC must bind the sequence")
	}
	if AnchorMAC(key, 1, sha256.Sum256([]byte("other journal"))) == m1 {
		t.Fatal("anchor MAC must bind the journal hash")
	}
}

func loadGolden(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse golden %s: %v", name, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestGoldenSubkeys(t *testing.T) {
	var gv struct {
		MasterKeyHex string `json:"master_key_hex"`
		VaultIDHex   string `json:"vault_id_hex"`
		StorageHex   string `json:"storage_hex"`
		JournalHex   string `json:"journal_hex"`
		PathHex      string `json:"path_hex"`
		AnchorHex    string `json:"anchor_hex"`
	}
	loadGolden(t, "gv5_subkeys.json", &gv)

	sk, err := DeriveSubkeys(mustHex(t, gv.MasterKeyHex), mustHex(t, gv.VaultIDHex))
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Destroy()
	for name, c := range map[string]struct {
		got  []byte
		want string
	}{
		"storage": {sk.Storage.Bytes(), gv.StorageHex},
		"journal": {sk.Journal.Bytes(), gv.JournalHex},
		"path":    {sk.Path.Bytes(), gv.PathHex},
		"anchor":  {sk.Anchor.Bytes(), gv.AnchorHex},
	} {
		if hex.EncodeToString(c.got) != c.want {
			t.Fatalf("%s subkey drifted from GV-5\ngot  %x\nwant %s", name, c.got, c.want)
		}
	}
}

func TestGoldenVerifier(t *testing.T) {
	var gv struct {
		CanonKDF      string `json:"canon_kdf"`
		VaultIDHex    string `json:"vault_id_hex"`
		JournalKeyHex string `json:"journal_key_hex"`
		NonceHex      string `json:"nonce_hex"`
		CiphertextHex string `json:"ciphertext_hex"`
	}
	loadGolden(t, "gv3_verifier.json", &gv)

	key := mustHex(t, gv.JournalKeyHex)
	nonce := mustHex(t, gv.NonceHex)
	ct := mustHex(t, gv.CiphertextHex)
	vaultID := mustHex(t, gv.VaultIDHex)

	if err := OpenAuthVerifier(key, nonce, ct, vaultID, gv.CanonKDF); err != nil {
		t.Fatalf("GV-3 must unlock with the recorded parameters: %v", err)
	}
	if err := OpenAuthVerifier(key, nonce, ct, vaultID, gv.CanonKDF+"x"); err == nil {
		t.Fatal("GV-3 must fail when the KDF block differs")
	}
	if len(ct) != len(VerifierPlaintext)+TagLen {
		t.Fatalf("GV-3 ciphertext length = %d", len(ct))
	}
}
