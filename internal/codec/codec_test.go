package codec

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRoundTripCompressible(t *testing.T) {
	src := bytes.Repeat([]byte("apex journal line, repeated many times. "), 4000)
	id, out, err := Compress(src)
	if err != nil {
		t.Fatal(err)
	}
	if id != Zstd {
		t.Fatalf("codec = %d, want zstd for compressible input", id)
	}
	if len(out) >= len(src)/2 {
		t.Fatalf("compressed %d -> %d, expected a large win", len(src), len(out))
	}
	back, err := Decompress(id, out, len(src))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, src) {
		t.Fatal("round trip mismatch")
	}
}

func TestSmallInputStaysUncompressed(t *testing.T) {
	src := []byte("tiny")
	id, out, err := Compress(src)
	if err != nil {
		t.Fatal(err)
	}
	if id != None {
		t.Fatalf("codec = %d, want none below MinCompressBytes", id)
	}
	if !bytes.Equal(out, src) {
		t.Fatal("payload changed")
	}
}

func TestRandomInputStaysUncompressed(t *testing.T) {
	src := make([]byte, 1<<20)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	id, out, err := Compress(src)
	if err != nil {
		t.Fatal(err)
	}
	if id != None {
		t.Fatalf("codec = %d, want none for random input", id)
	}
	if !bytes.Equal(out, src) {
		t.Fatal("payload changed")
	}
}

func TestDecompressRejectsOversize(t *testing.T) {
	src := bytes.Repeat([]byte("a"), 10000)
	id, out, err := Compress(src)
	if err != nil {
		t.Fatal(err)
	}
	if id != Zstd {
		t.Skip("input was not compressed")
	}
	if _, err := Decompress(id, out, 5000); err == nil {
		t.Fatal("expected an error for a declared length smaller than the payload")
	}
	if _, err := Decompress(None, out, 10); err == nil {
		t.Fatal("expected an error for oversized plaintext")
	}
	if _, err := Decompress(9, out, 100); err == nil {
		t.Fatal("expected an error for an unknown codec id")
	}
}
