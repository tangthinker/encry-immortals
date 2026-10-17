package index

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
)

func hmacOf(t *testing.T, path string) [32]byte {
	t.Helper()
	return vaultcrypto.PathHMAC(bytes.Repeat([]byte{7}, 32), []byte(path))
}

func TestEntryLifecycle(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	h := hmacOf(t, "photos/a.jpg")
	e := Entry{PathHMAC: h, Size: 123, MtimeNS: 456, CtimeNS: 789, ContentSHA256: [32]byte{1}, LastSeq: 3}
	if err := db.PutEntry(e); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.Entry(h)
	if err != nil || !ok {
		t.Fatalf("Entry = %v, %v", ok, err)
	}
	if got.Size != 123 || got.MtimeNS != 456 || got.CtimeNS != 789 || got.LastSeq != 3 {
		t.Fatalf("entry mismatch: %+v", got)
	}
	if err := db.DeleteEntry(h); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.Entry(h); err != nil || ok {
		t.Fatalf("entry should be gone: %v %v", ok, err)
	}
}

func TestAnchorAndCheckpoint(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, ok, err := db.LatestAnchor(); err != nil || ok {
		t.Fatalf("expected no anchor, got %v %v", ok, err)
	}
	if err := db.PutAnchor(2, [32]byte{2}, [32]byte{3}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutAnchor(7, [32]byte{7}, [32]byte{8}); err != nil {
		t.Fatal(err)
	}
	a, ok, err := db.LatestAnchor()
	if err != nil || !ok || a.Seq != 7 {
		t.Fatalf("LatestAnchor = %+v, %v, %v", a, ok, err)
	}

	if err := db.AddCheckpoint(5); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCheckpoint(9); err != nil {
		t.Fatal(err)
	}
	seq, ok, err := db.LatestCheckpoint()
	if err != nil || !ok || seq != 9 {
		t.Fatalf("LatestCheckpoint = %d, %v, %v", seq, ok, err)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetVaultID([]byte("vault-1")); err != nil {
		t.Fatal(err)
	}
	if err := db.SetLastSeq(42); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	seq, err := db2.LastSeq()
	if err != nil || seq != 42 {
		t.Fatalf("LastSeq = %d, %v", seq, err)
	}
	if v, ok, err := db2.VaultID(); err != nil || !ok || string(v) != "vault-1" {
		t.Fatalf("vault_id = %q, %v, %v", v, ok, err)
	}
}

func TestNoPlaintextPathsInStateDB(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := "family/photos/very-secret-name.jpg"
	h := hmacOf(t, secretPath)
	if err := db.PutEntry(Entry{PathHMAC: h, Size: 1, MtimeNS: 2, CtimeNS: 3, ContentSHA256: [32]byte{4}, LastSeq: 5}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// Check the main database file and its WAL, if any (I13).
	for _, name := range []string{"state.db", "state.db-wal"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(secretPath)) {
			t.Fatalf("%s contains a plaintext path", name)
		}
	}
}

func TestClearIndexKeepsAnchor(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutEntry(Entry{PathHMAC: hmacOf(t, "a"), LastSeq: 1}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutAnchor(1, [32]byte{1}, [32]byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := db.ClearIndex(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.Entry(hmacOf(t, "a")); ok {
		t.Fatal("entry survived ClearIndex")
	}
	if _, ok, _ := db.LatestAnchor(); !ok {
		t.Fatal("anchor must survive ClearIndex")
	}
	if err := db.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.LatestAnchor(); ok {
		t.Fatal("anchor survived Reset")
	}
}

func TestDrillAndExportTimestamps(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1773000000, 0)
	if err := db.MarkDrill(now); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkExport(now); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := db.Meta(MetaLastDrillUnix); !ok || v != "1773000000" {
		t.Fatalf("drill = %q %v", v, ok)
	}
	if v, ok, _ := db.Meta(MetaLastExportUnix); !ok || v != "1773000000" {
		t.Fatalf("export = %q %v", v, ok)
	}
}
