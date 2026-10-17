package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPackHeaderRoundTrip(t *testing.T) {
	h1, err := NewPackHeader(1773000000)
	if err != nil {
		t.Fatal(err)
	}
	h1.Flags = PackFlagHasFooter
	raw, err := h1.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != PackHeaderSize {
		t.Fatalf("header length %d", len(raw))
	}
	h2, err := ParsePackHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1.PackID, h2.PackID) || h1.CreatedUnix != h2.CreatedUnix || h2.Flags != PackFlagHasFooter {
		t.Fatalf("header mismatch: %+v vs %+v", h1, h2)
	}

	h3, err := NewPackHeader(1773000001)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(h1.PackID, h3.PackID) {
		t.Fatal("pack ids must be random")
	}
	if bytes.Equal(h1.Padding, h3.Padding) {
		t.Fatal("padding must be random")
	}
}

func TestPackHeaderRejectsInvalid(t *testing.T) {
	h, err := NewPackHeader(1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"short":        raw[:PackHeaderSize-1],
		"bad ver_alg":  mutate(raw, 16, 0x12),
		"unknown flag": mutate(raw, 17, 0x80),
		"reserved":     mutate(raw, 18, 0x01),
	}
	for name, in := range cases {
		if _, err := ParsePackHeader(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func mutate(in []byte, at int, v byte) []byte {
	out := append([]byte(nil), in...)
	out[at] = v
	return out
}

func TestFooterRoundTripAndLocate(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	packID := bytes.Repeat([]byte{0x55}, 16)
	footerStart := uint64(PackHeaderSize)
	entries := []FooterEntry{
		{Offset: 32, EnvLen: 54, PlainLen: 4, Index: 0},
		{Offset: 86, EnvLen: 60, PlainLen: 10, Index: 1},
		{Offset: 146, EnvLen: 50, PlainLen: 0, Index: 2},
	}
	footer, err := SealFooter(key, packID, footerStart, entries)
	if err != nil {
		t.Fatal(err)
	}
	fileSize := int64(footerStart) + int64(len(footer))

	last4 := footer[len(footer)-4:]
	start, length, err := LocateFooter(fileSize, last4)
	if err != nil {
		t.Fatal(err)
	}
	if start != footerStart || int(length) != len(footer) {
		t.Fatalf("located start=%d length=%d, want %d/%d", start, length, footerStart, len(footer))
	}
	back, err := OpenFooter(key, packID, start, footer)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(entries) {
		t.Fatalf("entry count %d", len(back))
	}
	for i := range entries {
		if back[i] != entries[i] {
			t.Fatalf("entry %d mismatch: %+v vs %+v", i, back[i], entries[i])
		}
	}

	// Truncation and tampering must be rejected.
	if _, err := OpenFooter(key, packID, start, footer[:len(footer)-1]); err == nil {
		t.Fatal("expected a truncated footer to be rejected")
	}
	if _, err := OpenFooter(key, packID, start, mutate(footer, len(footer)-20, footer[len(footer)-20]^0x01)); err == nil {
		t.Fatal("expected a tampered footer to be rejected")
	}
	if _, err := OpenFooter(key, packID, start+1, footer); err == nil {
		t.Fatal("expected a wrong footer start offset to be rejected")
	}
}

func TestLocateFooterRejectsBadTails(t *testing.T) {
	tail := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b
	}
	if _, _, err := LocateFooter(20, tail(50)); err == nil {
		t.Fatal("expected a too-short file to be rejected")
	}
	if _, _, err := LocateFooter(4096, tail(43)); err == nil {
		t.Fatal("expected a footer length below 44 to be rejected")
	}
	if _, _, err := LocateFooter(4096, tail(4096)); err == nil {
		t.Fatal("expected a footer length larger than the file to be rejected")
	}
	if _, _, err := LocateFooter(4096, nil); err == nil {
		t.Fatal("expected a missing tail to be rejected")
	}
}
