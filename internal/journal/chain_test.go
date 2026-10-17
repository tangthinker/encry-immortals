package journal

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func newLayout(t *testing.T) *store.Layout {
	t.Helper()
	l, err := store.NewLayout(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	return l
}

var (
	testJournalKey = bytes.Repeat([]byte{0x31}, 32)
	testVaultID    = bytes.Repeat([]byte{0x32}, 16)
)

func writeJournal(t *testing.T, l *store.Layout, seq uint64, prev [32]byte, ops []wire.Op) [32]byte {
	t.Helper()
	j := &wire.Journal{
		FormatVersion: wire.JournalFormatVersion,
		Seq:           seq,
		TxnID:         [16]byte{byte(seq)},
		TSUnix:        1773000000 + int64(seq),
		Msg:           "test journal",
		PrevHash:      prev,
		Flags:         wire.JournalFlagFinal,
		Kind:          wire.KindCommit,
		Params:        wire.VaultParams{SlicePlainBytes: 1 << 20, SmallFileBytes: 1 << 20, PackMaxBytes: 2 << 20, SessionMaxMiB: 1},
		Ops:           ops,
	}
	body, err := wire.EncodeJournalBody(j)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wire.SealJournalFile(testJournalKey, seq, testVaultID, body)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := l.AbsPath(l.JournalRelPath(seq))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFileDurableAs(l.StagingDir, l.JournalName(seq)+".tmp", abs, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(raw)
}

// addOp builds an empty-file ADD: a non-empty file must carry slices, and the
// wire decoder correctly rejects one without them.
func addOp(path string) wire.Op {
	return wire.Op{
		Type: wire.OpAdd, Path: path, Mode: 0o644, Size: 0,
		ModTimeNS:     1773000000000000000,
		ContentSHA256: sha256.Sum256([]byte(path)),
	}
}

func TestGenesisHash(t *testing.T) {
	want := sha256.Sum256([]byte("APEX-JOURNAL-GENESIS-v3"))
	if GenesisHash != want {
		t.Fatalf("genesis hash drifted: %x != %x", GenesisHash, want)
	}
}

func TestLoadReplaysChain(t *testing.T) {
	l := newLayout(t)
	h1 := writeJournal(t, l, 1, GenesisHash, []wire.Op{addOp("a.txt")})
	writeJournal(t, l, 2, h1, []wire.Op{addOp("dir/b.txt")})

	chain, err := Load(l, testJournalKey, testVaultID, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Files) != 2 || chain.LastSeq != 2 {
		t.Fatalf("chain files=%d last=%d", len(chain.Files), chain.LastSeq)
	}
	if _, ok := chain.Tree.Get("a.txt"); !ok {
		t.Fatal("a.txt missing from tree")
	}
	if _, ok := chain.Tree.Get("dir/b.txt"); !ok {
		t.Fatal("dir/b.txt missing from tree")
	}
	if len(chain.Tree.Packs) != 0 {
		t.Fatal("unexpected packs")
	}

	// Snapshot travel stops at the requested sequence.
	first, err := Load(l, testJournalKey, testVaultID, LoadOptions{TargetSeq: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.LastSeq != 1 {
		t.Fatalf("TargetSeq=1 gave last=%d", first.LastSeq)
	}
	if _, ok := first.Tree.Get("dir/b.txt"); ok {
		t.Fatal("snapshot at seq=1 must not contain later files")
	}
}

func TestLoadDetectsBrokenChain(t *testing.T) {
	l := newLayout(t)
	writeJournal(t, l, 1, GenesisHash, []wire.Op{addOp("a.txt")})
	// seq=2 with a wrong prev_hash must be rejected.
	writeJournal(t, l, 2, [32]byte{0xde, 0xad}, []wire.Op{addOp("b.txt")})
	if _, err := Load(l, testJournalKey, testVaultID, LoadOptions{}); err == nil {
		t.Fatal("expected prev_hash mismatch to be detected")
	} else if apexerr.CodeOf(err) != apexerr.CodeChain {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeChain)
	}
}

func TestLoadDetectsMissingJournal(t *testing.T) {
	l := newLayout(t)
	h1 := writeJournal(t, l, 1, GenesisHash, []wire.Op{addOp("a.txt")})
	writeJournal(t, l, 2, h1, []wire.Op{addOp("b.txt")})
	writeJournal(t, l, 3, [32]byte{}, []wire.Op{addOp("c.txt")})
	// Remove the middle journal: the gap must be reported, not silently ignored.
	abs, err := l.AbsPath(l.JournalRelPath(2))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(abs); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(l, testJournalKey, testVaultID, LoadOptions{}); err == nil {
		t.Fatal("expected a gap to be detected")
	} else if apexerr.CodeOf(err) != apexerr.CodeChain {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeChain)
	}
}

func TestLoadDetectsTampering(t *testing.T) {
	l := newLayout(t)
	writeJournal(t, l, 1, GenesisHash, []wire.Op{addOp("a.txt")})
	abs, err := l.AbsPath(l.JournalRelPath(1))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(abs, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(l, testJournalKey, testVaultID, LoadOptions{}); err == nil {
		t.Fatal("expected tampering to be detected")
	}
}

func TestLoadRejectsRenumberedJournal(t *testing.T) {
	l := newLayout(t)
	writeJournal(t, l, 1, GenesisHash, []wire.Op{addOp("a.txt")})
	// Copy 00000001.journal to 00000002.journal: seq is bound in the AAD.
	src, err := l.AbsPath(l.JournalRelPath(1))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := l.AbsPath(l.JournalRelPath(2))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(l, testJournalKey, testVaultID, LoadOptions{}); err == nil {
		t.Fatal("expected a renumbered journal to fail decryption")
	}
}

func TestApplyOpsRules(t *testing.T) {
	l := newLayout(t)
	h1 := writeJournal(t, l, 1, GenesisHash, []wire.Op{
		{Type: wire.OpMkdir, Path: "d", Mode: 0o755},
		{Type: wire.OpAdd, Path: "d/f", Mode: 0o644, Size: 0, ContentSHA256: sha256.Sum256([]byte("f"))},
		{Type: wire.OpSymlink, Path: "l", Mode: 0o777, Extra: "d/f"},
	})
	writeJournal(t, l, 2, h1, []wire.Op{
		{Type: wire.OpModify, Path: "no-such-file", Mode: 0o644, Size: 0, ContentSHA256: sha256.Sum256([]byte("x"))},
		{Type: wire.OpDelete, Path: "absent"},
		{Type: wire.OpMkdir, Path: "d", Mode: 0o700},
	})
	chain, err := Load(l, testJournalKey, testVaultID, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	node, ok := chain.Tree.Get("no-such-file")
	if !ok || node.Kind != KindFile {
		t.Fatal("MODIFY to a missing path must behave like ADD")
	}
	if node, ok := chain.Tree.Get("d"); !ok || node.Mode != 0o700 {
		t.Fatalf("second MKDIR must win: %+v", node)
	}
	if link, ok := chain.Tree.Get("l"); !ok || link.LinkTarget != "d/f" {
		t.Fatalf("symlink node wrong: %+v", link)
	}
}

func TestRmdirNonEmptyIsRejected(t *testing.T) {
	l := newLayout(t)
	h1 := writeJournal(t, l, 1, GenesisHash, []wire.Op{
		{Type: wire.OpMkdir, Path: "d", Mode: 0o755},
		{Type: wire.OpAdd, Path: "d/f", Mode: 0o644, Size: 0, ContentSHA256: sha256.Sum256([]byte("f"))},
	})
	writeJournal(t, l, 2, h1, []wire.Op{
		{Type: wire.OpRmdir, Path: "d"},
	})
	if _, err := Load(l, testJournalKey, testVaultID, LoadOptions{}); err == nil {
		t.Fatal("expected RMDIR on a non-empty directory to be rejected")
	}
	_ = filepath.Join
}
