// Command goldengen regenerates the golden vectors under testdata/golden.
//
// Regeneration is deliberate, never automatic: a diff in these files means the
// wire format or a crypto dependency changed (spec §12.3). Always review the
// diff and, if the change is intended, bump the wire version.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tangthinker/encry-immortals/internal/armor"
	"github.com/tangthinker/encry-immortals/internal/codec"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func main() {
	out := flag.String("out", "testdata/golden", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}
	write(filepath.Join(*out, "gv5_subkeys.json"), gv5())
	write(filepath.Join(*out, "gv1_slice.json"), gv1())
	write(filepath.Join(*out, "gv2_journal.json"), gv2())
	write(filepath.Join(*out, "gv3_verifier.json"), gv3())
	write(filepath.Join(*out, "gv4_armor.json"), gv4())
	fmt.Println("golden vectors written to", *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "goldengen:", err)
	os.Exit(1)
}

func write(path string, v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		fail(err)
	}
	fmt.Println("wrote", path)
}

// gv1 freezes a slice envelope for a fixed key, nonce and AAD inputs. The
// payload is stored with codec=none on purpose so that the vector stays stable
// across zstd versions; compression is covered by GV-2 (journal file).
func gv1() any {
	key := sha256.Sum256([]byte("apex-golden-storage-key-v1"))
	packID := idBytes()
	txnID := seqBytes(0x40, 16)
	nonce := seqBytes(0x60, 24)
	plain := []byte("apex golden slice payload")
	env, err := wire.SealSliceWithNonce(key[:], codec.None, len(plain), plain, packID, 32, 0, txnID, nonce)
	if err != nil {
		fail(err)
	}
	return map[string]any{
		"key_hex":      hex.EncodeToString(key[:]),
		"pack_id_hex":  hex.EncodeToString(packID),
		"txn_id_hex":   hex.EncodeToString(txnID),
		"nonce_hex":    hex.EncodeToString(nonce),
		"offset":       32,
		"index":        0,
		"codec":        codec.None,
		"plain_hex":    hex.EncodeToString(plain),
		"envelope_hex": hex.EncodeToString(env),
	}
}

// gv2 freezes a journal body (msgpack) and its encrypted container.
func gv2() any {
	key := sha256.Sum256([]byte("apex-golden-journal-key-v1"))
	vaultID := idBytes()
	const seq = uint64(7)
	nonce := seqBytes(0x80, 24)
	prev := sha256.Sum256([]byte("apex-golden-prev-journal"))
	j := &wire.Journal{
		FormatVersion: wire.JournalFormatVersion,
		Seq:           seq,
		TxnID:         [16]byte{0xa0, 0xa1, 0xa2},
		TSUnix:        1773000000,
		Msg:           "golden vector",
		PrevHash:      prev,
		Flags:         wire.JournalFlagFinal,
		Kind:          wire.KindCommit,
		Params: wire.VaultParams{
			SlicePlainBytes: 32 << 20,
			SmallFileBytes:  64 << 20,
			PackMaxBytes:    128 << 20,
			SessionMaxMiB:   256,
		},
		Packs: []wire.PackRef{{
			Name:       "data/2026-10/pack_1773000000123_a1b2c3.dat",
			Size:       4096,
			SHA256:     sha256.Sum256([]byte("golden pack")),
			SliceCount: 1,
		}},
		Dirs: []wire.DirEntry{{Path: "photos", Mode: 0o755, ModTimeNS: 1773000000000000000}},
		Ops: []wire.Op{{
			Type: wire.OpAdd, Path: "photos/a.jpg", Mode: 0o644, Size: 1024,
			ModTimeNS:     1773000000000000000,
			ContentSHA256: sha256.Sum256([]byte("golden file")),
			Slices: []wire.SliceRef{{
				PackIdx: 0, Offset: 32, EnvLen: 1074, PlainLen: 1024, Index: 0,
				Codec: codec.Zstd, PlainSHA256: sha256.Sum256([]byte("golden slice")),
			}},
		}},
	}
	body, err := wire.EncodeJournalBody(j)
	if err != nil {
		fail(err)
	}
	file, err := wire.SealJournalFileWithNonce(key[:], seq, vaultID, body, nonce)
	if err != nil {
		fail(err)
	}
	return map[string]any{
		"key_hex":      hex.EncodeToString(key[:]),
		"vault_id_hex": hex.EncodeToString(vaultID),
		"seq":          seq,
		"nonce_hex":    hex.EncodeToString(nonce),
		"body_hex":     hex.EncodeToString(body),
		"file_hex":     hex.EncodeToString(file),
	}
}

// gv5 freezes the four HKDF child keys for a fixed MasterKey + vault_id.
func gv5() any {
	master := sha256.Sum256([]byte("apex-golden-master-key-v1"))
	vaultID := idBytes()
	sk, err := vaultcrypto.DeriveSubkeys(master[:], vaultID)
	if err != nil {
		fail(err)
	}
	defer sk.Destroy()
	return map[string]string{
		"master_key_hex": hex.EncodeToString(master[:]),
		"vault_id_hex":   hex.EncodeToString(vaultID),
		"storage_hex":    hex.EncodeToString(sk.Storage.Bytes()),
		"journal_hex":    hex.EncodeToString(sk.Journal.Bytes()),
		"path_hex":       hex.EncodeToString(sk.Path.Bytes()),
		"anchor_hex":     hex.EncodeToString(sk.Anchor.Bytes()),
	}
}

// gv3 freezes the auth_verifier ciphertext for a fixed key, nonce and AAD.
func gv3() any {
	journalKey := sha256.Sum256([]byte("apex-golden-journal-key-v1"))
	vaultID := idBytes()
	nonce := bytes.Repeat([]byte{0x20}, 24)
	for i := range nonce {
		nonce[i] = byte(0x20 + i)
	}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(0x10 + i)
	}
	canon := "argon2id|t=3|m=262144|p=4|k=32|salt=" + base64.RawURLEncoding.EncodeToString(salt)

	aad, err := vaultcrypto.VerifierAAD(vaultcrypto.VerAlg, vaultID, canon)
	if err != nil {
		fail(err)
	}
	ct, err := vaultcrypto.Seal(journalKey[:], nonce, []byte(vaultcrypto.VerifierPlaintext), aad)
	if err != nil {
		fail(err)
	}
	return map[string]string{
		"canon_kdf":       canon,
		"vault_id_hex":    hex.EncodeToString(vaultID),
		"journal_key_hex": hex.EncodeToString(journalKey[:]),
		"nonce_hex":       hex.EncodeToString(nonce),
		"ciphertext_hex":  hex.EncodeToString(ct),
		"plaintext":       vaultcrypto.VerifierPlaintext,
	}
}

// gv4 freezes Crockford Base32 encoding plus the CRC-bearing Armor envelope.
func gv4() any {
	type vector struct {
		PayloadHex string `json:"payload_hex"`
		Encoded    string `json:"encoded"`
	}
	payloads := [][]byte{
		{},
		{0x00},
		{0xff},
		[]byte("Hello"),
		seqBytes(0x00, 32),
		bytes.Repeat([]byte("APEX"), 75),
	}
	vectors := make([]vector, 0, len(payloads))
	for _, p := range payloads {
		vectors = append(vectors, vector{PayloadHex: hex.EncodeToString(p), Encoded: armor.Encode(p)})
	}
	return map[string]any{
		"prefix":  armor.Prefix,
		"vectors": vectors,
		"corrupt_cases": []map[string]any{
			{"input": "U", "must_be_rejected": true},
			{"input": "!", "must_be_rejected": true},
			{"input": "A", "must_be_rejected": true},
			{"input": "AB", "must_be_rejected": true},
		},
	}
}

func idBytes() []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func seqBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}
