package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/codec"
)

func sampleJournal() *Journal {
	return &Journal{
		FormatVersion: JournalFormatVersion,
		Seq:           5,
		TxnID:         [16]byte{1, 2, 3},
		TSUnix:        1773000000,
		Msg:           "日常增量",
		PrevHash:      [32]byte{9},
		Flags:         JournalFlagFinal,
		Kind:          KindCommit,
		Params: VaultParams{
			SlicePlainBytes: 32 << 20,
			SmallFileBytes:  64 << 20,
			PackMaxBytes:    128 << 20,
			SessionMaxMiB:   256,
		},
		Packs: []PackRef{{
			Name:       "data/2026-10/pack_1773000000123_a1b2c3.dat",
			Size:       1234,
			SHA256:     [32]byte{7},
			SliceCount: 1,
		}},
		Dirs: []DirEntry{{Path: "a", Mode: 0o755, ModTimeNS: 111}},
		Ops: []Op{
			{
				Type: OpAdd, Path: "a/b.txt", Mode: 0o644, Size: 4, ModTimeNS: 5,
				ContentSHA256: [32]byte{4},
				Slices: []SliceRef{{
					PackIdx: 0, Offset: 32, EnvLen: 54, PlainLen: 4, Index: 0,
					Codec: codec.None, PlainSHA256: [32]byte{2},
				}},
			},
			{Type: OpMkdir, Path: "empty", Mode: 0o755, ModTimeNS: 6},
			{Type: OpSymlink, Path: "link", Mode: 0o777, ModTimeNS: 7, Extra: "a/b.txt"},
			{Type: OpDelete, Path: "gone", Mode: 0o644, ModTimeNS: 8},
			{Type: OpMeta, Path: "a/b.txt", Mode: 0o600, Size: 4, ModTimeNS: 9},
		},
	}
}

func TestJournalBodyRoundTrip(t *testing.T) {
	j := sampleJournal()
	raw, err := EncodeJournalBody(j)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeJournalBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, j) {
		t.Fatalf("round trip mismatch\ngot  %+v\nwant %+v", back, j)
	}
	// Canonical encoding: encoding twice produces identical bytes.
	raw2, err := EncodeJournalBody(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatal("encoding is not byte-stable")
	}
}

func TestCheckpointJournalRoundTrip(t *testing.T) {
	j := sampleJournal()
	j.Kind = KindCheckpoint
	j.Ops = nil
	j.Tree = []FileNode{
		{Path: "a/b.txt", Mode: 0o644, Size: 4, ModTimeNS: 5, ContentSHA256: [32]byte{4},
			Slices: []SliceRef{{PackIdx: 0, Offset: 32, EnvLen: 54, PlainLen: 4, Index: 0, Codec: codec.None, PlainSHA256: [32]byte{2}}}},
		{Path: "empty.txt", Mode: 0o644, Size: 0, ModTimeNS: 6},
	}
	raw, err := EncodeJournalBody(j)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeJournalBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, j) {
		t.Fatalf("checkpoint round trip mismatch")
	}
}

func TestJournalDecoderRejectsMalformed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Journal)
	}{
		{"version 4", func(j *Journal) { j.FormatVersion = 4 }},
		{"unknown flags", func(j *Journal) { j.Flags = 0x02 }},
		{"unknown kind", func(j *Journal) { j.Kind = 3 }},
		{"slice index gap", func(j *Journal) { j.Ops[0].Slices[0].Index = 5 }},
		{"pack idx out of range", func(j *Journal) { j.Ops[0].Slices[0].PackIdx = 1 }},
		{"nonempty file without slices", func(j *Journal) { j.Ops[0].Slices = nil }},
		{"zero file with slices", func(j *Journal) { j.Ops[0].Size = 0 }},
		{"delete with slices", func(j *Journal) { j.Ops[3].Slices = j.Ops[0].Slices }},
		{"delete with extra", func(j *Journal) { j.Ops[3].Extra = "x" }},
		{"symlink without target", func(j *Journal) { j.Ops[2].Extra = "" }},
		{"absolute path", func(j *Journal) { j.Ops[0].Path = "/etc/passwd" }},
		{"dotdot path", func(j *Journal) { j.Ops[0].Path = "a/../../etc/passwd" }},
		{"empty path", func(j *Journal) { j.Ops[0].Path = "" }},
		{"empty segment", func(j *Journal) { j.Ops[0].Path = "a//b" }},
		{"bad pack name", func(j *Journal) { j.Packs[0].Name = "etc/passwd" }},
		{"pack name without data prefix", func(j *Journal) { j.Packs[0].Name = "pack_1_abcdef.dat" }},
		{"type bits in mode", func(j *Journal) { j.Ops[0].Mode = 0o100644 }},
	}
	for _, c := range cases {
		j := sampleJournal()
		c.mutate(j)
		raw := encodeJournalBodyRaw(j)
		if _, err := DecodeJournalBody(raw); err == nil {
			t.Errorf("%s: decoder accepted malformed journal", c.name)
		}
		if _, err := EncodeJournalBody(j); err == nil {
			t.Errorf("%s: encoder accepted malformed journal", c.name)
		}
	}
}

func TestJournalDecoderRejectsTrailingBytes(t *testing.T) {
	raw, err := EncodeJournalBody(sampleJournal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeJournalBody(append(raw, 0x00)); err == nil {
		t.Fatal("expected trailing bytes to be rejected")
	}
}

func TestJournalFileRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	vaultID := bytes.Repeat([]byte{0x77}, 16)
	body, err := EncodeJournalBody(sampleJournal())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealJournalFile(key, 5, vaultID, body)
	if err != nil {
		t.Fatal(err)
	}
	back, err := OpenJournalFile(key, 5, vaultID, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, body) {
		t.Fatal("journal file round trip mismatch")
	}

	if _, err := OpenJournalFile(key, 6, vaultID, raw); err == nil {
		t.Fatal("expected a wrong seq to break decryption")
	}
	otherVault := append([]byte(nil), vaultID...)
	otherVault[0] ^= 0xff
	if _, err := OpenJournalFile(key, 5, otherVault, raw); err == nil {
		t.Fatal("expected a wrong vault_id to break decryption")
	}
	if _, err := OpenJournalFile(key, 5, vaultID, mutate(raw, JournalFileHeaderSize, raw[JournalFileHeaderSize]^0x01)); err == nil {
		t.Fatal("expected tampered ciphertext to be rejected")
	}
	if _, err := OpenJournalFile(key, 5, vaultID, mutate(raw, 2, 0x01)); err == nil {
		t.Fatal("expected a nonzero reserved field to be rejected")
	}
	if _, err := OpenJournalFile(key, 5, vaultID, mutate(raw, 0, 0x12)); err == nil {
		t.Fatal("expected a bad ver_alg to be rejected")
	}
	if _, err := OpenJournalFile(key, 5, vaultID, raw[:JournalFileMinSize-1]); err == nil {
		t.Fatal("expected a short journal file to be rejected")
	}
}
