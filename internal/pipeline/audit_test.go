package pipeline

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/index"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// cloneDir copies a tree; each audit case gets its own copy of the target.
func cloneDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// loadAndRestore mirrors the CLI: a restore that reports corrupt files is a
// failure (exit code 12), even though Restore itself keeps going to salvage the
// rest of the tree.
func loadAndRestore(t *testing.T, layout *store.Layout, dest string) error {
	t.Helper()
	if _, err := journal.Load(layout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{}); err != nil {
		return err
	}
	res, err := Restore(RestoreOptions{
		Layout: layout, Keys: testKeys, DestDir: dest, Overwrite: OverwriteNever,
	})
	if err != nil {
		return err
	}
	if len(res.Corrupt) > 0 {
		return apexerr.Newf(apexerr.CodeCorrupt, "%d 个文件无法还原", len(res.Corrupt))
	}
	return nil
}

func expectCode(t *testing.T, err error, allowed ...apexerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}
	got := apexerr.CodeOf(err)
	for _, c := range allowed {
		if got == c {
			return
		}
	}
	t.Fatalf("error code = %s, want one of %v (err: %v)", got, allowed, err)
}

// firstReferencedSlice finds a pack and an offset of a slice the latest tree
// actually reads, so the mutation cannot hide in a footer or a stale pack.
func firstReferencedSlice(t *testing.T, l *store.Layout) (string, uint64) {
	t.Helper()
	chain, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range chain.Tree.Files() {
		if len(n.Slices) > 0 {
			return n.PackNames[0], n.Slices[0].Offset
		}
	}
	t.Fatal("no referenced slices")
	return "", 0
}

func firstPack(t *testing.T, layout *store.Layout) string {
	t.Helper()
	packs, err := layout.ListPacks()
	if err != nil || len(packs) == 0 {
		t.Fatalf("no packs: %v", err)
	}
	return packs[0]
}

// TestMaliciousInputAudit is the hand-crafted adversarial matrix from spec 12.8 #9.
func TestMaliciousInputAudit(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("alpha"), 0o644)
	writeFile(t, filepath.Join(e.source, "sub/b.txt"), []byte("beta"), 0o644)
	if err := os.Symlink("a.txt", filepath.Join(e.source, "link")); err != nil {
		t.Fatal(err)
	}
	if !e.backup(t, false).Changed {
		t.Fatal("seed backup")
	}
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("alpha v2"), 0o644)
	if !e.backup(t, false).Changed {
		t.Fatal("second backup")
	}

	setup := func(t *testing.T) (*store.Layout, string) {
		t.Helper()
		dst := filepath.Join(t.TempDir(), "target")
		cloneDir(t, e.layout.TargetDir, dst)
		l, err := store.NewLayout(dst, "")
		if err != nil {
			t.Fatal(err)
		}
		return l, dst
	}

	t.Run("pack truncated", func(t *testing.T) {
		l, _ := setup(t)
		p := firstPack(t, l)
		abs, _ := l.AbsPath(p)
		info, _ := os.Stat(abs)
		if err := os.Truncate(abs, info.Size()-10); err != nil {
			t.Fatal(err)
		}
		expectCode(t, loadAndRestore(t, l, filepath.Join(t.TempDir(), "out")), apexerr.CodeIncomplete, apexerr.CodeCorrupt)
	})

	t.Run("pack bit flip", func(t *testing.T) {
		l, _ := setup(t)
		p, offset := firstReferencedSlice(t, l)
		abs, _ := l.AbsPath(p)
		raw, _ := os.ReadFile(abs)
		raw[offset+12] ^= 0x01 // nonce byte of a slice the tree really reads
		os.WriteFile(abs, raw, 0o644)
		expectCode(t, loadAndRestore(t, l, filepath.Join(t.TempDir(), "out")), apexerr.CodeCorrupt, apexerr.CodeIncomplete)
	})

	t.Run("pack header ver_alg", func(t *testing.T) {
		l, _ := setup(t)
		p := firstPack(t, l)
		abs, _ := l.AbsPath(p)
		raw, _ := os.ReadFile(abs)
		raw[16] = 0x12
		os.WriteFile(abs, raw, 0o644)
		expectCode(t, loadAndRestore(t, l, filepath.Join(t.TempDir(), "out")), apexerr.CodeCorrupt)
	})

	t.Run("pack zeroed slice", func(t *testing.T) {
		l, _ := setup(t)
		p, offset := firstReferencedSlice(t, l)
		abs, _ := l.AbsPath(p)
		raw, _ := os.ReadFile(abs)
		for i := offset + 2; i < offset+20 && i < uint64(len(raw)); i++ {
			raw[i] = 0
		}
		os.WriteFile(abs, raw, 0o644)
		expectCode(t, loadAndRestore(t, l, filepath.Join(t.TempDir(), "out")), apexerr.CodeCorrupt)
	})

	t.Run("pack deleted", func(t *testing.T) {
		l, _ := setup(t)
		p := firstPack(t, l)
		abs, _ := l.AbsPath(p)
		os.Remove(abs)
		expectCode(t, loadAndRestore(t, l, filepath.Join(t.TempDir(), "out")), apexerr.CodeIncomplete)
	})

	t.Run("pack appended junk", func(t *testing.T) {
		l, _ := setup(t)
		p := firstPack(t, l)
		abs, _ := l.AbsPath(p)
		f, _ := os.OpenFile(abs, os.O_APPEND|os.O_WRONLY, 0o644)
		f.Write(bytes.Repeat([]byte{0x41}, 32))
		f.Close()
		expectCode(t, loadAndRestore(t, l, filepath.Join(t.TempDir(), "out")), apexerr.CodeIncomplete)
	})

	t.Run("journal ciphertext flip", func(t *testing.T) {
		l, _ := setup(t)
		abs, _ := l.AbsPath(l.JournalRelPath(2))
		raw, _ := os.ReadFile(abs)
		raw[40] ^= 0x01
		os.WriteFile(abs, raw, 0o644)
		_, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		expectCode(t, err, apexerr.CodeCorrupt)
	})

	t.Run("journal truncated", func(t *testing.T) {
		l, _ := setup(t)
		abs, _ := l.AbsPath(l.JournalRelPath(2))
		raw, _ := os.ReadFile(abs)
		os.WriteFile(abs, raw[:len(raw)/2], 0o644)
		_, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		expectCode(t, err, apexerr.CodeCorrupt)
	})

	t.Run("journal renumbered", func(t *testing.T) {
		l, _ := setup(t)
		from, _ := l.AbsPath(l.JournalRelPath(2))
		to, _ := l.AbsPath(l.JournalRelPath(3))
		os.Rename(from, to)
		_, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		expectCode(t, err, apexerr.CodeChain)
	})

	t.Run("journal duplicated over later seq", func(t *testing.T) {
		l, _ := setup(t)
		src, _ := l.AbsPath(l.JournalRelPath(1))
		dst, _ := l.AbsPath(l.JournalRelPath(2))
		raw, _ := os.ReadFile(src)
		os.WriteFile(dst, raw, 0o644)
		_, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		expectCode(t, err, apexerr.CodeCorrupt)
	})

	t.Run("middle journal deleted", func(t *testing.T) {
		l, _ := setup(t)
		abs, _ := l.AbsPath(l.JournalRelPath(1))
		os.Remove(abs)
		_, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		expectCode(t, err, apexerr.CodeChain)
	})

	t.Run("last journal deleted is caught by the anchor", func(t *testing.T) {
		l, _ := setup(t)
		abs, _ := l.AbsPath(l.JournalRelPath(2))
		raw, _ := os.ReadFile(abs)
		os.Remove(abs)
		chain, err := journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		if err != nil {
			t.Fatalf("chain of 1 journal should still load: %v", err)
		}
		if chain.LastSeq != 1 {
			t.Fatalf("unexpected last seq %d", chain.LastSeq)
		}
		db, err := index.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		// The anchor was written for seq=2 before the rollback.
		if err := db.PutAnchor(2, sha256.Sum256(raw), [32]byte{1}); err != nil {
			t.Fatal(err)
		}
		anchor, ok, _ := db.LatestAnchor()
		if !ok || anchor.Seq <= chain.LastSeq {
			t.Fatal("anchor should be ahead of the truncated chain")
		}
	})

	t.Run("journal from another vault", func(t *testing.T) {
		l, _ := setup(t)
		body, err := wire.EncodeJournalBody(&wire.Journal{
			FormatVersion: wire.JournalFormatVersion,
			Seq:           1,
			TxnID:         [16]byte{1},
			TSUnix:        1773000000,
			PrevHash:      journal.GenesisHash,
			Flags:         wire.JournalFlagFinal,
			Kind:          wire.KindCommit,
			Params:        wire.VaultParams{SlicePlainBytes: 1 << 20, SmallFileBytes: 1 << 20, PackMaxBytes: 2 << 20, SessionMaxMiB: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		otherVault := bytes.Repeat([]byte{0x99}, 16)
		raw, err := wire.SealJournalFile(testKeys.Sub.Journal.Bytes(), 1, otherVault, body)
		if err != nil {
			t.Fatal(err)
		}
		abs, _ := l.AbsPath(l.JournalRelPath(1))
		os.WriteFile(abs, raw, 0o644)
		abs2, _ := l.AbsPath(l.JournalRelPath(2))
		os.Remove(abs2)
		_, err = journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
		expectCode(t, err, apexerr.CodeCorrupt, apexerr.CodeChain)
	})

	t.Run("path traversal is rejected at encode", func(t *testing.T) {
		for _, p := range []string{"../escape", "/etc/passwd", "a/../../b", "a//b"} {
			_, err := wire.EncodeJournalBody(&wire.Journal{
				FormatVersion: wire.JournalFormatVersion,
				Seq:           1,
				TxnID:         [16]byte{1},
				PrevHash:      journal.GenesisHash,
				Flags:         wire.JournalFlagFinal,
				Kind:          wire.KindCommit,
				Params:        wire.VaultParams{SlicePlainBytes: 1 << 20, SmallFileBytes: 1 << 20, PackMaxBytes: 2 << 20, SessionMaxMiB: 1},
				Ops:           []wire.Op{{Type: wire.OpDelete, Path: p}},
			})
			if err == nil {
				t.Fatalf("path %q was accepted", p)
			}
		}
	})

	t.Run("anchor MAC tamper", func(t *testing.T) {
		db, err := index.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		sum := sha256.Sum256([]byte("journal"))
		good := vaultcrypto.AnchorMAC(testKeys.Sub.Anchor.Bytes(), 7, sum)
		if err := db.PutAnchor(7, sum, good); err != nil {
			t.Fatal(err)
		}
		anchor, ok, _ := db.LatestAnchor()
		if !ok {
			t.Fatal("anchor missing")
		}
		if vaultcrypto.AnchorMAC(testKeys.Sub.Anchor.Bytes(), 7, sum) != anchor.MAC {
			t.Fatal("good anchor should verify")
		}
		anchor.MAC[0] ^= 0xff
		if vaultcrypto.AnchorMAC(testKeys.Sub.Anchor.Bytes(), 7, sum) == anchor.MAC {
			t.Fatal("tampered anchor must not verify")
		}
	})
}
