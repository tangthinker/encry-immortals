package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestGoldenSliceEnvelope(t *testing.T) {
	var gv struct {
		KeyHex      string `json:"key_hex"`
		PackIDHex   string `json:"pack_id_hex"`
		TxnIDHex    string `json:"txn_id_hex"`
		NonceHex    string `json:"nonce_hex"`
		Offset      uint64 `json:"offset"`
		Index       uint32 `json:"index"`
		Codec       byte   `json:"codec"`
		PlainHex    string `json:"plain_hex"`
		EnvelopeHex string `json:"envelope_hex"`
	}
	loadGolden(t, "gv1_slice.json", &gv)

	key := mustHex(t, gv.KeyHex)
	packID := mustHex(t, gv.PackIDHex)
	txnID := mustHex(t, gv.TxnIDHex)
	plain := mustHex(t, gv.PlainHex)
	env := mustHex(t, gv.EnvelopeHex)

	got, _, _, err := OpenSlice(key, env, packID, gv.Offset, gv.Index, txnID)
	if err != nil {
		t.Fatalf("GV-1 must decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("GV-1 plaintext mismatch\ngot  %x\nwant %x", got, plain)
	}
	h, err := ParseSliceHeader(env)
	if err != nil {
		t.Fatalf("GV-1 header: %v", err)
	}
	if h.Codec != gv.Codec || int(h.PlainLen) != len(plain) {
		t.Fatalf("GV-1 header mismatch: %+v", h)
	}
}

func TestGoldenJournalFile(t *testing.T) {
	var gv struct {
		KeyHex     string `json:"key_hex"`
		VaultIDHex string `json:"vault_id_hex"`
		Seq        uint64 `json:"seq"`
		NonceHex   string `json:"nonce_hex"`
		BodyHex    string `json:"body_hex"`
		FileHex    string `json:"file_hex"`
	}
	loadGolden(t, "gv2_journal.json", &gv)

	key := mustHex(t, gv.KeyHex)
	vaultID := mustHex(t, gv.VaultIDHex)
	body := mustHex(t, gv.BodyHex)
	file := mustHex(t, gv.FileHex)

	got, err := OpenJournalFile(key, gv.Seq, vaultID, file)
	if err != nil {
		t.Fatalf("GV-2 must decrypt: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("GV-2 body mismatch\ngot  %x\nwant %x", got, body)
	}
	j, err := DecodeJournalBody(got)
	if err != nil {
		t.Fatalf("GV-2 body decode: %v", err)
	}
	if j.Seq != gv.Seq || j.Msg != "golden vector" {
		t.Fatalf("GV-2 content mismatch: seq=%d msg=%q", j.Seq, j.Msg)
	}
	// Renaming the journal must break decryption (seq is bound in the AAD).
	if _, err := OpenJournalFile(key, gv.Seq+1, vaultID, file); err == nil {
		t.Fatal("GV-2 must fail when the file is renumbered")
	}
	// Re-encoding the decoded body must reproduce the frozen bytes exactly.
	reencoded, err := EncodeJournalBody(j)
	if err != nil {
		t.Fatalf("GV-2 re-encode: %v", err)
	}
	if !bytes.Equal(reencoded, body) {
		t.Fatal("GV-2 body encoding drifted")
	}
}
