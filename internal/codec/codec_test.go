package codec

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestRoundTripCompressible(t *testing.T) {
	src := bytes.Repeat([]byte("eimmortal journal line, repeated many times. "), 4000)
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

func TestLevelsRoundTripAndImprove(t *testing.T) {
	src := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog 0123456789 "), 8000)
	sizes := map[int]int{}
	for _, level := range []int{MinLevel, 3, 5, 9, 19, MaxLevel} {
		id, out, err := CompressWith(src, Options{Level: level})
		if err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		if id != Zstd {
			t.Fatalf("level %d: codec = %d", level, id)
		}
		back, err := Decompress(id, out, len(src))
		if err != nil || !bytes.Equal(back, src) {
			t.Fatalf("level %d: round trip failed: %v", level, err)
		}
		sizes[level] = len(out)
	}
	if sizes[MinLevel] <= sizes[19] {
		t.Fatalf("expected higher levels to compress better: level1=%d level19=%d", sizes[MinLevel], sizes[19])
	}
	t.Logf("compressed %d bytes: level1=%d level3=%d level5=%d level9=%d level19=%d level22=%d",
		len(src), sizes[MinLevel], sizes[3], sizes[5], sizes[9], sizes[19], sizes[MaxLevel])
}

func TestClampsInvalidLevels(t *testing.T) {
	src := bytes.Repeat([]byte("abc"), 5000)
	for _, level := range []int{-5, 0, 999} {
		id, out, err := CompressWith(src, Options{Level: level})
		if err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		if id != Zstd {
			t.Fatalf("level %d produced no compression", level)
		}
		back, err := Decompress(id, out, len(src))
		if err != nil || !bytes.Equal(back, src) {
			t.Fatalf("level %d round trip failed: %v", level, err)
		}
	}
}

func TestMinBytesIsHonoured(t *testing.T) {
	src := bytes.Repeat([]byte("x"), 1000)
	if id, _, err := CompressWith(src, Options{MinBytes: 4096}); err != nil || id != None {
		t.Fatalf("default threshold: id=%d err=%v", id, err)
	}
	id, out, err := CompressWith(src, Options{MinBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if id != Zstd {
		t.Fatalf("threshold 1 should compress: id=%d", id)
	}
	back, err := Decompress(id, out, len(src))
	if err != nil || !bytes.Equal(back, src) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestSmallInputStaysUncompressed(t *testing.T) {
	src := []byte("tiny")
	id, out, err := Compress(src)
	if err != nil {
		t.Fatal(err)
	}
	if id != None {
		t.Fatalf("codec = %d, want none below MinBytes", id)
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

// BenchmarkCompressLevels reports the throughput/size trade-off used to pick a
// default. Run: go test ./internal/codec -bench CompressLevels -benchmem
func BenchmarkCompressLevels(b *testing.B) {
	src := make([]byte, 1<<20)
	for i := range src {
		src[i] = byte('a' + (i*7)%23)
	}
	for _, level := range []int{1, 3, 5, 9, 19} {
		level := level
		b.Run(fmt.Sprintf("level%d", level), func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			for i := 0; i < b.N; i++ {
				if _, _, err := CompressWith(src, Options{Level: level}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
