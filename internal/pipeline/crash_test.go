package pipeline

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/codec"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
)

// Simulates crash point K4 (pack published, journal never written) and checks
// that the next run still succeeds and the orphan is not referenced.
func TestInterruptedCommitLeavesOrphanOnly(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("payload"), 0o644)

	txn := [16]byte{0xaa}
	pw, err := store.NewPackWriter(e.layout, testKeys.Sub.Storage.Bytes(), txn, 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("orphan slice content")
	codecID, compressed, err := codec.Compress(content)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Append(codecID, len(content), compressed, sha256.Sum256(content), 0); err != nil {
		t.Fatal(err)
	}
	packs, err := pw.SealAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected one orphan pack, got %d", len(packs))
	}
	packsOnDisk, err := e.layout.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packsOnDisk) != 1 {
		t.Fatalf("orphan pack missing: %v", packsOnDisk)
	}

	res := e.backup(t, false)
	if !res.Changed || res.Seq != 1 {
		t.Fatalf("backup after orphan: %+v", res)
	}
	chain, err := journal.Load(e.layout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := chain.Tree.Packs[packs[0].Name]; ok {
		t.Fatal("orphan pack must not be referenced by any journal")
	}

	dest := filepath.Join(e.root, "restored")
	e.restore(t, dest, 0)
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("restored content = %q, %v", got, err)
	}
}

// Simulates crash point K5 (journal left in .tmp/) and K7 (state.db lost).
func TestStagingLeftoverAndStateLossAreRecoverable(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("v1"), 0o644)
	if err := e.layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(e.layout.StagingDir, "00000001.journal.tmp")
	if err := os.WriteFile(leftover, []byte("half written"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := timeNowMinus48h()
	if err := os.Chtimes(leftover, old, old); err != nil {
		t.Fatal(err)
	}
	res := e.backup(t, false)
	if !res.Changed {
		t.Fatal("backup with leftover staging file failed to commit")
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatal("stale staging file was not swept")
	}

	// Losing state.db must not change the diff result (I14 at the pipeline level).
	e2 := newEnv(t)
	writeFile(t, filepath.Join(e2.source, "a.txt"), []byte("v1"), 0o644)
	if !e2.backup(t, false).Changed {
		t.Fatal("first backup should change")
	}
	if e2.backup(t, false).Changed {
		t.Fatal("second backup should be a no-op")
	}
	if err := os.Remove(filepath.Join(e2.root, "state.db")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if e2.backup(t, false).Changed {
		t.Fatal("backup depended on state.db for the diff (must replay journals instead)")
	}
}

// The commit sequence must be strictly increasing and the chain hash-linked.
func TestChainGrowsContiguously(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 3; i++ {
		writeFile(t, filepath.Join(e.source, "f.txt"), bytes.Repeat([]byte{byte('0' + i)}, 10+i), 0o644)
		res := e.backup(t, false)
		if res.Seq != uint64(i+1) {
			t.Fatalf("commit %d got seq %d", i+1, res.Seq)
		}
	}
	chain, err := journal.Load(e.layout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Files) != 3 {
		t.Fatalf("chain has %d files", len(chain.Files))
	}
	for i, f := range chain.Files {
		if f.Body.Seq != uint64(i+1) {
			t.Fatalf("file %d has seq %d", i, f.Body.Seq)
		}
	}
}
