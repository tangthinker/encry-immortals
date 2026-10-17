package store

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func TestPackWriterReaderRoundTrip(t *testing.T) {
	l := newTestLayout(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	txn := [16]byte{1, 2, 3}

	w, err := NewPackWriter(l, key, txn, 4096, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()

	var refs []wire.SliceRef
	var contents [][]byte
	for i := 0; i < 12; i++ {
		content := bytes.Repeat([]byte{byte('a' + i)}, 500)
		codecID, payload, err := codec.Compress(content)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := w.Append(codecID, len(content), payload, sha256.Sum256(content), 0)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
		contents = append(contents, content)
	}
	packs, err := w.SealAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) < 2 {
		t.Fatalf("expected rollover into several packs, got %d", len(packs))
	}

	// Pack files must exist with the recorded size and SHA-256.
	for _, p := range packs {
		abs, err := l.AbsPath(p.Name)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(abs)
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(raw)) != p.Size {
			t.Fatalf("%s size %d != recorded %d", p.Name, len(raw), p.Size)
		}
		if sha256.Sum256(raw) != p.SHA256 {
			t.Fatalf("%s sha256 mismatch", p.Name)
		}
		// The footer must be locatable and self-consistent.
		start, length, err := wire.LocateFooter(int64(len(raw)), raw[len(raw)-4:])
		if err != nil {
			t.Fatalf("%s footer: %v", p.Name, err)
		}
		header, err := wire.ParsePackHeader(raw[:wire.PackHeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		entries, err := wire.OpenFooter(key, header.PackID, start, raw[start:start+uint64(length)])
		if err != nil {
			t.Fatalf("%s footer decrypt: %v", p.Name, err)
		}
		if uint32(len(entries)) != p.SliceCount {
			t.Fatalf("%s footer entries %d != %d", p.Name, len(entries), p.SliceCount)
		}
	}

	rd, err := NewPackReader(l, key)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	for i, ref := range refs {
		p := packs[ref.PackIdx]
		h, err := rd.Open(p.Name, p.Size)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rd.ReadSlice(h, ref, txn)
		if err != nil {
			t.Fatalf("slice %d: %v", i, err)
		}
		if !bytes.Equal(got, contents[i]) {
			t.Fatalf("slice %d content mismatch", i)
		}
	}
}

func TestPackReaderRejectsWrongContext(t *testing.T) {
	l := newTestLayout(t)
	key := bytes.Repeat([]byte{0x43}, 32)
	txn := [16]byte{9}
	w, err := NewPackWriter(l, key, txn, 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("hello apex")
	codecID, payload, err := codec.Compress(content)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := w.Append(codecID, len(content), payload, sha256.Sum256(content), 0)
	if err != nil {
		t.Fatal(err)
	}
	packs, err := w.SealAll()
	if err != nil {
		t.Fatal(err)
	}
	p := packs[0]

	rd, err := NewPackReader(l, key)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	// Wrong txn id: the slice is bound to its transaction (I3).
	otherTxn := [16]byte{8}
	h, err := rd.Open(p.Name, p.Size)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.ReadSlice(h, ref, otherTxn); err == nil {
		t.Fatal("expected a different txn_id to fail authentication")
	}

	// Wrong expected size: E13 ("pack still syncing").
	rd2, err := NewPackReader(l, key)
	if err != nil {
		t.Fatal(err)
	}
	defer rd2.Close()
	if _, err := rd2.Open(p.Name, p.Size+1); err == nil {
		t.Fatal("expected a size mismatch to be reported")
	} else if apexerr.CodeOf(err) != apexerr.CodeIncomplete {
		t.Fatalf("size mismatch code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeIncomplete)
	}

	// Tampered ciphertext must be detected.
	abs, err := l.AbsPath(p.Name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	raw[wire.PackHeaderSize+12] ^= 0x01
	if err := os.WriteFile(abs, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	rd3, err := NewPackReader(l, key)
	if err != nil {
		t.Fatal(err)
	}
	defer rd3.Close()
	h3, err := rd3.Open(p.Name, p.Size)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd3.ReadSlice(h3, ref, txn); err == nil {
		t.Fatal("expected tampered bytes to be rejected")
	} else if apexerr.CodeOf(err) != apexerr.CodeCorrupt {
		t.Fatalf("tamper code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeCorrupt)
	}
	if err := rd3.VerifyPack(p); err == nil {
		t.Fatal("expected VerifyPack to detect the tampered pack")
	}
}

func TestPackWriterAbortLeavesNoVisiblePack(t *testing.T) {
	l := newTestLayout(t)
	key := bytes.Repeat([]byte{0x44}, 32)
	w, err := NewPackWriter(l, key, [16]byte{1}, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("aborted")
	codecID, payload, err := codec.Compress(content)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(codecID, len(content), payload, sha256.Sum256(content), 0); err != nil {
		t.Fatal(err)
	}
	w.Abort()

	entries, err := os.ReadDir(l.StagingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("abort left %d staging entries", len(entries))
	}
	packs, err := l.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 0 {
		t.Fatalf("abort published %d packs", len(packs))
	}
}

func TestPackWriterEmptySeal(t *testing.T) {
	l := newTestLayout(t)
	w, err := NewPackWriter(l, bytes.Repeat([]byte{0x45}, 32), [16]byte{1}, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	packs, err := w.SealAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 0 {
		t.Fatalf("empty writer sealed %d packs", len(packs))
	}
}

func TestPackWriterRejectsOversizedUnit(t *testing.T) {
	l := newTestLayout(t)
	key := bytes.Repeat([]byte{0x46}, 32)
	w, err := NewPackWriter(l, key, [16]byte{1}, 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	content := bytes.Repeat([]byte("x"), 200)
	if _, err := w.Append(codec.None, len(content), content, sha256.Sum256(content), 0); err == nil {
		t.Fatal("expected an oversized slice to be rejected")
	}
}

func TestPackWriterValidatesConfig(t *testing.T) {
	l := newTestLayout(t)
	if _, err := NewPackWriter(l, bytes.Repeat([]byte{1}, 31), [16]byte{}, 1<<20, 10); err == nil {
		t.Fatal("expected a short key to be rejected")
	}
	if _, err := NewPackWriter(l, bytes.Repeat([]byte{1}, 32), [16]byte{}, 10, 10); err == nil {
		t.Fatal("expected a tiny pack_max_bytes to be rejected")
	}
	if _, err := NewPackWriter(l, bytes.Repeat([]byte{1}, 32), [16]byte{}, 1<<20, 0); err == nil {
		t.Fatal("expected maxSlices=0 to be rejected")
	}
}

func TestStagingTmpFileNameIsCamouflaged(t *testing.T) {
	l := newTestLayout(t)
	key := bytes.Repeat([]byte{0x47}, 32)
	w, err := NewPackWriter(l, key, [16]byte{1}, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("camouflage")
	codecID, payload, err := codec.Compress(content)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(codecID, len(content), payload, sha256.Sum256(content), 0); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(l.StagingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one staging file, got %d", len(entries))
	}
	name := entries[0].Name()
	if len(name) < 10 || name[:5] != "pack_" || filepath.Ext(name) != ".dat" {
		t.Fatalf("staging file name is not camouflaged: %q", name)
	}
	w.Abort()
}
