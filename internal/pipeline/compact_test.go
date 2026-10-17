package pipeline

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

func countPacks(t *testing.T, l *store.Layout) int {
	t.Helper()
	packs, err := l.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	return len(packs)
}

func TestCompactSameIdentity(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("v1"), 0o644)
	writeFile(t, filepath.Join(e.source, "gone.txt"), []byte("bye"), 0o644)
	writeFile(t, filepath.Join(e.source, "sub/keep.txt"), []byte("keep"), 0o600)
	if err := os.Symlink("a.txt", filepath.Join(e.source, "link")); err != nil {
		t.Fatal(err)
	}
	if !e.backup(t, false).Changed {
		t.Fatal("first backup should change")
	}
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("v2 longer"), 0o644)
	if err := os.Remove(filepath.Join(e.source, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	if !e.backup(t, false).Changed {
		t.Fatal("second backup should change")
	}
	oldPacks := countPacks(t, e.layout)

	out := filepath.Join(e.root, "compact-out")
	res, err := Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: out,
	})
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if res.Seq != 1 || res.Files != 2 || res.Dirs < 1 || res.Links != 1 {
		t.Fatalf("compact result: %+v", res)
	}
	if len(res.Dropped) != 0 {
		t.Fatalf("unexpected dropped files: %v", res.Dropped)
	}

	newLayout, err := store.NewLayout(out, "")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := journal.Load(newLayout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatalf("load compacted chain: %v", err)
	}
	if chain.LastSeq != 1 || len(chain.Files) != 1 {
		t.Fatalf("compacted chain: last=%d files=%d", chain.LastSeq, len(chain.Files))
	}
	if _, ok := chain.Tree.Get("gone.txt"); ok {
		t.Fatal("deleted file materialised in the compacted vault")
	}

	dest := filepath.Join(e.root, "restored-from-compact")
	_, err = Restore(RestoreOptions{
		Layout: newLayout, Keys: testKeys, Config: e.cfg, DestDir: dest, Overwrite: OverwriteNever,
	})
	if err != nil {
		t.Fatalf("restore from compacted vault: %v", err)
	}
	assertTreesEqual(t, e.source, dest)

	// The old vault must be untouched (I1: compact never deletes).
	if got := countPacks(t, e.layout); got != oldPacks {
		t.Fatalf("old vault pack count changed: %d -> %d", oldPacks, got)
	}
	if _, err := os.Stat(filepath.Join(e.layout.MetaDir, "00000002.journal")); err != nil {
		t.Fatalf("old journals were removed: %v", err)
	}
}

func TestCompactNewIdentity(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("content"), 0o644)
	if !e.backup(t, false).Changed {
		t.Fatal("backup should change")
	}
	newVault := filepath.Join(e.root, "vault-new")
	out := filepath.Join(e.root, "compact-new-id")
	newPassword := []byte("brand-new-password-123456")
	res, err := Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: out,
		NewIdentity: true, NewVaultDir: newVault, NewPassword: newPassword,
		Probe: func(p vaultcrypto.KDFParams) time.Duration { return 3000 * time.Millisecond },
	})
	if err != nil {
		t.Fatalf("compact --new-identity: %v", err)
	}
	if res.NewVaultID == "" || res.ArmorKey == "" {
		t.Fatalf("missing new identity output: %+v", res)
	}
	if res.NewVaultID == base64.RawURLEncoding.EncodeToString(testKeys.VaultID[:]) || res.NewVaultID == "" {
		t.Fatal("vault_id did not change")
	}
	meta, err := vault.LoadMeta(newVault)
	if err != nil {
		t.Fatalf("load new vault.meta: %v", err)
	}
	if meta.VaultID != res.NewVaultID {
		t.Fatalf("new vault.meta id mismatch")
	}
	newKeys, err := meta.Unlock(newPassword)
	if err != nil {
		t.Fatalf("unlock new vault with new password: %v", err)
	}
	defer newKeys.Destroy()
	if _, err := meta.Unlock([]byte("pipeline-test-password")); err == nil {
		t.Fatal("old password must not unlock the new identity")
	}
	newLayout, err := store.NewLayout(out, "")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(e.root, "restored-new-id")
	if _, err := Restore(RestoreOptions{
		Layout: newLayout, Keys: newKeys, Config: e.cfg, DestDir: dest, Overwrite: OverwriteNever,
	}); err != nil {
		t.Fatalf("restore from new identity: %v", err)
	}
	assertTreesEqual(t, e.source, dest)

	// The new control plane must already carry a matching anchor.
	if _, err := os.Stat(filepath.Join(newVault, vault.StateFileName)); err != nil {
		t.Fatalf("new state.db missing: %v", err)
	}
}

func TestCompactMissingPack(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("alpha"), 0o644)
	if !e.backup(t, false).Changed {
		t.Fatal("backup should change")
	}
	chain, err := journal.Load(e.layout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Tree.Packs) == 0 {
		t.Fatal("no packs in the tree")
	}
	var packName string
	for name := range chain.Tree.Packs {
		packName = name
		break
	}
	abs, err := e.layout.AbsPath(packName)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(abs); err != nil {
		t.Fatal(err)
	}

	_, err = Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: filepath.Join(e.root, "out-strict"),
	})
	if err == nil {
		t.Fatal("expected compact to fail when a pack is missing")
	}
	if apexerr.CodeOf(err) != apexerr.CodeIncomplete {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeIncomplete)
	}

	res, err := Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: filepath.Join(e.root, "out-lossy"),
		AcceptDataLoss: true,
	})
	if err != nil {
		t.Fatalf("compact --accept-data-loss: %v", err)
	}
	if len(res.Dropped) != 1 || res.Dropped[0] != "a.txt" {
		t.Fatalf("dropped list = %v", res.Dropped)
	}
}

func TestCompactRefusesNonEmptyOutAndDryRun(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("x"), 0o644)
	if !e.backup(t, false).Changed {
		t.Fatal("backup should change")
	}
	busy := filepath.Join(e.root, "busy")
	if err := os.MkdirAll(busy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(busy, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: busy,
	}); err == nil {
		t.Fatal("expected a non-empty output directory to be refused")
	}

	dryOut := filepath.Join(e.root, "dry-out")
	res, err := Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: dryOut, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run compact: %v", err)
	}
	if res.Files != 1 || !res.DryRun {
		t.Fatalf("dry-run result: %+v", res)
	}
	if _, err := os.Stat(dryOut); !os.IsNotExist(err) {
		t.Fatal("dry-run created the output directory")
	}
}

func TestCompactAtSeqKeepsHistoryFile(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(e.source, "keep.txt"), []byte("v1"), 0o644)
	writeFile(t, filepath.Join(e.source, "later.txt"), []byte("later"), 0o644)
	if !e.backup(t, false).Changed {
		t.Fatal("backup 1")
	}
	if err := os.Remove(filepath.Join(e.source, "later.txt")); err != nil {
		t.Fatal(err)
	}
	if !e.backup(t, false).Changed {
		t.Fatal("backup 2")
	}
	out := filepath.Join(e.root, "compact-at-1")
	if _, err := Compact(CompactOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, OutDir: out, AtSeq: 1,
	}); err != nil {
		t.Fatalf("compact --at 1: %v", err)
	}
	newLayout, err := store.NewLayout(out, "")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := journal.Load(newLayout, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := chain.Tree.Get("later.txt"); !ok {
		t.Fatal("compact --at 1 lost a file that existed at seq 1")
	}
	if data, _ := os.ReadFile(filepath.Join(e.source, "keep.txt")); !bytes.Equal(data, []byte("v1")) {
		t.Fatal("source changed unexpectedly")
	}
}
