package pipeline

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/config"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

var testKeys *vault.Keys

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "apex-pipeline-keys")
	if err != nil {
		panic(err)
	}
	params := vaultcrypto.KDFParams{
		Algorithm: vaultcrypto.KDFAlgArgon2id,
		Time:      vaultcrypto.KDFTimeMin,
		MemoryKiB: vaultcrypto.KDFMemoryKiBMin,
		Threads:   4,
		KeyLen:    vaultcrypto.KeyLen,
		Salt:      bytes.Repeat([]byte{0x11}, vaultcrypto.SaltLen),
	}
	meta, err := vault.NewMeta([]byte("pipeline-test-password"), params, time.Now())
	if err != nil {
		panic(err)
	}
	testKeys, err = meta.Unlock([]byte("pipeline-test-password"))
	if err != nil {
		panic(err)
	}
	code := m.Run()
	testKeys.Destroy()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	layout *store.Layout
	cfg    *config.Config
	source string
	root   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	layout, err := store.NewLayout(filepath.Join(root, "target"), "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Storage.SlicePlainBytes = 64 << 10
	cfg.Storage.SmallFileBytes = 256 << 10
	cfg.Storage.PackMaxBytes = 1 << 20
	cfg.Scan.Exclude = nil
	cfg.OnChange.Strategy = "retry"
	return &env{layout: layout, cfg: cfg, source: source, root: root}
}

func (e *env) backup(t *testing.T, dryRun bool) *BackupResult {
	t.Helper()
	res, err := Backup(BackupOptions{
		Layout:    e.layout,
		Keys:      testKeys,
		Config:    e.cfg,
		SourceDir: e.source,
		Message:   "test commit",
		DryRun:    dryRun,
	})
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	return res
}

func (e *env) restore(t *testing.T, dest string, atSeq uint64) *RestoreResult {
	t.Helper()
	res, err := Restore(RestoreOptions{
		Layout:    e.layout,
		Keys:      testKeys,
		Config:    e.cfg,
		DestDir:   dest,
		AtSeq:     atSeq,
		Overwrite: OverwriteNever,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	return res
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	e := newEnv(t)
	// Regular small file.
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("hello eimmortal"), 0o644)
	// Empty file.
	writeFile(t, filepath.Join(e.source, "empty.bin"), nil, 0o600)
	// Large file: three slices at 64 KiB.
	big := bytes.Repeat([]byte("0123456789abcdef"), 10000) // 160 KiB
	writeFile(t, filepath.Join(e.source, "big.bin"), big, 0o644)
	// Nested dir + file, and an empty dir.
	writeFile(t, filepath.Join(e.source, "sub/deep/c.txt"), []byte("nested"), 0o640)
	if err := os.MkdirAll(filepath.Join(e.source, "empty-dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Symlink inside the source.
	if err := os.Symlink("a.txt", filepath.Join(e.source, "link-a")); err != nil {
		t.Fatal(err)
	}

	res := e.backup(t, false)
	if !res.Changed || res.Seq != 1 {
		t.Fatalf("first backup: changed=%v seq=%d", res.Changed, res.Seq)
	}
	if res.Stats.Added != 4 || res.Stats.Dirs < 3 || res.Stats.Links != 1 {
		t.Fatalf("unexpected stats: %+v", res.Stats)
	}
	if len(res.Packs) == 0 || res.PackBytes == 0 {
		t.Fatalf("no packs written: %+v", res)
	}

	// Second run must be a no-op (I8).
	again := e.backup(t, false)
	if again.Changed {
		t.Fatalf("second backup produced a journal: %+v", again)
	}

	dest := filepath.Join(e.root, "restored")
	rres := e.restore(t, dest, 0)
	if rres.Files != 4 || rres.Dirs < 3 || rres.Links != 1 {
		t.Fatalf("restore result: %+v", rres)
	}
	assertTreesEqual(t, e.source, dest)
}

func TestBackupDetectsChangesAndSnapshotTravel(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "keep.txt"), []byte("v1"), 0o644)
	writeFile(t, filepath.Join(e.source, "gone.txt"), []byte("bye"), 0o644)
	first := e.backup(t, false)
	if first.Seq != 1 {
		t.Fatalf("seq = %d", first.Seq)
	}

	// Modify one file, delete another, add a directory with a file.
	writeFile(t, filepath.Join(e.source, "keep.txt"), []byte("v2-longer"), 0o644)
	if err := os.Remove(filepath.Join(e.source, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.source, "newdir/f.txt"), []byte("new"), 0o644)

	second := e.backup(t, false)
	if !second.Changed || second.Seq != 2 {
		t.Fatalf("second backup: %+v", second)
	}
	if second.Stats.Added != 1 || second.Stats.Modified != 1 || second.Stats.Deleted != 1 || second.Stats.Dirs != 1 {
		t.Fatalf("unexpected stats: %+v", second.Stats)
	}

	latest := filepath.Join(e.root, "latest")
	e.restore(t, latest, 0)
	assertTreesEqual(t, e.source, latest)
	if _, err := os.Stat(filepath.Join(latest, "gone.txt")); !os.IsNotExist(err) {
		t.Fatal("deleted file was restored")
	}

	firstSnap := filepath.Join(e.root, "first")
	e.restore(t, firstSnap, 1)
	if data, err := os.ReadFile(filepath.Join(firstSnap, "keep.txt")); err != nil || string(data) != "v1" {
		t.Fatalf("snapshot at seq=1 has wrong content: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(firstSnap, "gone.txt")); err != nil {
		t.Fatal("snapshot at seq=1 should still contain gone.txt")
	}
}

func TestBackupDetectsMetaOnlyChange(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.source, "chmod-me.txt")
	writeFile(t, path, []byte("content"), 0o644)
	e.backup(t, false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	res := e.backup(t, false)
	if !res.Changed || res.Stats.Meta != 1 {
		t.Fatalf("expected a META op, got %+v", res.Stats)
	}
	dest := filepath.Join(e.root, "restored")
	e.restore(t, dest, 0)
	info, err := os.Stat(filepath.Join(dest, "chmod-me.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestBackupDryRunWritesNothing(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "x.txt"), []byte("x"), 0o644)
	res := e.backup(t, true)
	if !res.Changed || res.EstimatedOps == 0 {
		t.Fatalf("dry run result: %+v", res)
	}
	seqs, err := e.layout.ListJournals()
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 0 {
		t.Fatalf("dry run wrote journals: %v", seqs)
	}
	packs, err := e.layout.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 0 {
		t.Fatalf("dry run wrote packs: %v", packs)
	}
}

func TestRestoreRefusesNonEmptyDest(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("a"), 0o644)
	e.backup(t, false)
	dest := filepath.Join(e.root, "occupied")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dest, "foreign.txt"), []byte("do not touch"), 0o644)
	_, err := Restore(RestoreOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, DestDir: dest, Overwrite: OverwriteNever,
	})
	if err == nil {
		t.Fatal("expected a non-empty destination to be refused")
	}
	if apexerr.CodeOf(err) != apexerr.CodeUsage {
		t.Fatalf("code = %s", apexerr.CodeOf(err))
	}
}

func TestBackupRejectsTargetPollution(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("a"), 0o644)
	if err := os.MkdirAll(e.layout.RootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.layout.RootDir, "README.md"), []byte("nope"), 0o644)
	_, err := Backup(BackupOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, SourceDir: e.source,
	})
	if err == nil {
		t.Fatal("expected target pollution to be rejected")
	}
	if apexerr.CodeOf(err) != apexerr.CodeCorrupt {
		t.Fatalf("code = %s", apexerr.CodeOf(err))
	}
}

func TestBackupRejectsOverlappingDirectories(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.layout.RootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Backup(BackupOptions{
		Layout:    e.layout,
		Keys:      testKeys,
		Config:    e.cfg,
		SourceDir: e.root,
	})
	if err == nil {
		t.Fatal("expected overlapping source and target to be rejected")
	}
}

func TestJournalChainAfterBackups(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("a"), 0o644)
	e.backup(t, false)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("changed"), 0o644)
	e.backup(t, false)
	chain, err := journal.Load(e.layout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if chain.LastSeq != 2 || len(chain.Files) != 2 {
		t.Fatalf("chain last seq = %d, files = %d", chain.LastSeq, len(chain.Files))
	}
	node, ok := chain.Tree.Get("a.txt")
	if !ok || node.Size != uint64(len("changed")) {
		t.Fatalf("tree node wrong: %+v", node)
	}
	if len(node.PackNames) != len(node.Slices) || len(node.Slices) == 0 {
		t.Fatalf("pack names not resolved: %+v", node)
	}
	if node.ContentSHA256 != sha256.Sum256([]byte("changed")) {
		t.Fatal("content hash mismatch")
	}
}

// assertTreesEqual compares two trees: contents, modes, mtimes and links.
func assertTreesEqual(t *testing.T, want, got string) {
	t.Helper()
	wantEntries := walkTree(t, want)
	gotEntries := walkTree(t, got)
	if len(wantEntries) != len(gotEntries) {
		t.Fatalf("entry count mismatch: want %d, got %d\nwant=%v\ngot=%v",
			len(wantEntries), len(gotEntries), keysOf(wantEntries), keysOf(gotEntries))
	}
	for rel, w := range wantEntries {
		g, ok := gotEntries[rel]
		if !ok {
			t.Fatalf("missing %s in restored tree", rel)
		}
		if w.kind != g.kind {
			t.Fatalf("%s: kind %v != %v", rel, w.kind, g.kind)
		}
		if w.kind == "symlink" {
			if w.target != g.target {
				t.Fatalf("%s: link target %q != %q", rel, w.target, g.target)
			}
			continue
		}
		if w.mode != g.mode {
			t.Fatalf("%s: mode %o != %o", rel, w.mode, g.mode)
		}
		if w.kind == "file" {
			if w.sha != g.sha {
				t.Fatalf("%s: content differs", rel)
			}
		}
		if w.mtime != g.mtime {
			t.Fatalf("%s: mtime %d != %d", rel, w.mtime, g.mtime)
		}
	}
}

type treeEntry struct {
	kind   string
	mode   os.FileMode
	mtime  int64
	sha    [32]byte
	target string
}

func walkTree(t *testing.T, root string) map[string]treeEntry {
	t.Helper()
	out := make(map[string]treeEntry)
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		e := treeEntry{mtime: info.ModTime().UnixNano()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			e.kind = "symlink"
			target, _ := os.Readlink(p)
			e.target = target
			e.mtime = 0 // symlink mtimes are not restored
		case info.IsDir():
			e.kind = "dir"
			e.mode = info.Mode().Perm()
		default:
			e.kind = "file"
			e.mode = info.Mode().Perm()
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			e.sha = sha256.Sum256(data)
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keysOf(m map[string]treeEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCompressionLevelAffectsPackSize proves the configured zstd level actually
// reaches the pack writer (before this, codec.zstd_level was ignored).
func TestCompressionLevelAffectsPackSize(t *testing.T) {
	// Real-ish text (the spec documents) so that level 19 has something to win.
	var corpus bytes.Buffer
	for i := 0; i < 3; i++ {
		matches, err := filepath.Glob("../../docs/spec/*.md")
		if err != nil || len(matches) == 0 {
			t.Skip("spec documents not available")
		}
		for _, m := range matches {
			raw, err := os.ReadFile(m)
			if err != nil {
				t.Fatal(err)
			}
			corpus.Write(raw)
		}
	}
	data := corpus.Bytes()
	run := func(level int) (packBytes, plainBytes uint64) {
		e := newEnv(t)
		e.cfg.Codec.ZstdLevel = level
		e.cfg.Codec.MinCompressBytes = 1
		e.cfg.Storage.SlicePlainBytes = 8 << 20
		e.cfg.Storage.SmallFileBytes = 8 << 20
		e.cfg.Storage.PackMaxBytes = 16 << 20
		writeFile(t, filepath.Join(e.source, "text.md"), data, 0o644)
		res := e.backup(t, false)
		return res.PackBytes, res.PlainBytes
	}
	lowPack, lowPlain := run(1)
	highPack, highPlain := run(19)
	if lowPlain != highPlain || lowPlain == 0 {
		t.Fatalf("plain bytes differ: %d vs %d", lowPlain, highPlain)
	}
	if highPack >= lowPack {
		t.Fatalf("level 19 (%d bytes) should be smaller than level 1 (%d bytes)", highPack, lowPack)
	}
	t.Logf("plain=%d level1=%d level19=%d (saved %d bytes)", lowPlain, lowPack, highPack, lowPack-highPack)
}
