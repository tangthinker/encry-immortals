package pipeline

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/codec"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func testPack(name string) wire.PackRef {
	sum := sha256.Sum256([]byte(name))
	return wire.PackRef{Name: name, Size: 4096, SHA256: sum, SliceCount: 2}
}

func TestManifestRoundTrip(t *testing.T) {
	pack := testPack("data/2026-10/pack_1792335033338_abcdef.dat")
	txn := [16]byte{1, 2, 3}
	content := sha256.Sum256([]byte("hello"))
	slice := sha256.Sum256([]byte("hello"))
	ops := []wire.Op{{
		Type: wire.OpAdd, Path: "docs/a.txt", Mode: 0o644, Size: 5,
		ContentSHA256: content,
		Slices: []wire.SliceRef{{
			PackIdx: 0, Offset: 0, EnvLen: 80, PlainLen: 5, Index: 0,
			Codec: codec.None, PlainSHA256: slice,
		}},
	}}
	doc, ok, err := buildManifest([]wire.PackRef{pack}, 0, ops, txn, 7)
	if err != nil || !ok {
		t.Fatalf("buildManifest: ok=%v err=%v", ok, err)
	}
	if doc.Pack != pack.Name || doc.Seq != 7 || len(doc.Ops) != 1 {
		t.Fatalf("unexpected manifest: %+v", doc)
	}
	plain, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sealManifest(testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], pack.Name, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openManifest(testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], pack.Name, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pack != pack.Name || len(got.Ops) != 1 || got.Ops[0].Path != "docs/a.txt" {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	// A manifest is bound to its pack name and to its ciphertext.
	if _, err := openManifest(testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:],
		"data/2026-10/pack_1792335033338_ffffff.dat", raw); err == nil {
		t.Fatal("manifest accepted under a different pack name")
	}
	raw[len(raw)-1] ^= 0xff
	if _, err := openManifest(testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], pack.Name, raw); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestManifestMultiPackOp(t *testing.T) {
	packs := []wire.PackRef{
		testPack("data/2026-10/pack_1792335033338_aaaaaa.dat"),
		testPack("data/2026-10/pack_1792335033338_bbbbbb.dat"),
	}
	sum := sha256.Sum256([]byte("x"))
	ops := []wire.Op{{
		Type: wire.OpAdd, Path: "big.bin", Mode: 0o644, Size: 10,
		ContentSHA256: sum,
		Slices: []wire.SliceRef{
			{PackIdx: 0, Offset: 0, EnvLen: 80, PlainLen: 5, Index: 0, Codec: codec.None, PlainSHA256: sum},
			{PackIdx: 1, Offset: 0, EnvLen: 80, PlainLen: 5, Index: 1, Codec: codec.None, PlainSHA256: sum},
		},
	}}
	for i := range packs {
		doc, ok, err := buildManifest(packs, i, ops, [16]byte{}, 1)
		if err != nil || !ok {
			t.Fatalf("pack %d: ok=%v err=%v", i, ok, err)
		}
		if len(doc.Ops) != 1 || len(doc.Ops[0].Packs) != 2 || len(doc.Ops[0].Slices) != 2 {
			t.Fatalf("pack %d manifest lost the multi-pack file: %+v", i, doc.Ops)
		}
	}
}

func TestBackupWritesOneManifestPerPack(t *testing.T) {
	e := newEnv(t)
	e.cfg.Scan.IgnoreXattr = true
	writeFile(t, filepath.Join(e.source, "a.txt"), []byte("alpha"), 0o644)
	writeFile(t, filepath.Join(e.source, "b.txt"), []byte("bravo"), 0o644)
	e.backup(t, false)

	packs, err := e.layout.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	manifests, err := e.layout.ListManifests()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != len(packs) {
		t.Fatalf("manifests=%d packs=%d", len(manifests), len(packs))
	}
	for _, name := range packs {
		rel := e.layout.ManifestRelPath(name)
		abs, err := e.layout.AbsPath(rel)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read manifest for %s: %v", name, err)
		}
		doc, err := openManifest(testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], name, raw)
		if err != nil {
			t.Fatalf("open manifest for %s: %v", name, err)
		}
		if doc.Pack != name || len(doc.Ops) == 0 {
			t.Fatalf("manifest for %s is wrong: %+v", name, doc)
		}
	}
}

func TestRestoreListPacksAndSkipMissing(t *testing.T) {
	e := newEnv(t)
	e.cfg.Scan.IgnoreXattr = true
	// Two ~900 KiB incompressible files force more than one 1 MiB pack.
	big := make([]byte, 900<<10)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.source, "a.bin"), big, 0o644)
	writeFile(t, filepath.Join(e.source, "b.bin"), big, 0o644)
	e.backup(t, false)

	plans, err := Restore(RestoreOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, ListPacks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	packs, err := e.layout.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(plans.PackPlans) != len(packs) {
		t.Fatalf("plans=%d packs=%d", len(plans.PackPlans), len(packs))
	}
	for _, p := range plans.PackPlans {
		if !p.Present || p.Size == 0 {
			t.Fatalf("unexpected plan: %+v", p)
		}
	}
	if len(packs) < 2 {
		t.Fatalf("expected at least 2 packs, got %d", len(packs))
	}

	victim := packs[0]
	abs, err := e.layout.AbsPath(victim)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(abs); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(e.root, "restore")
	res, err := Restore(RestoreOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, DestDir: dest,
		Overwrite: OverwriteNever, SkipMissingPacks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete || len(res.MissingPacks) == 0 || len(res.MissingFiles) == 0 {
		t.Fatalf("expected an incomplete restore: %+v", res)
	}

	if err := os.WriteFile(abs, saved, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Restore(RestoreOptions{
		Layout: e.layout, Keys: testKeys, Config: e.cfg, DestDir: dest,
		Overwrite: OverwriteNever, SkipMissingPacks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Incomplete {
		t.Fatalf("restore still incomplete after restoring the pack: %+v", res)
	}
	assertTreesEqual(t, e.source, dest)
}
