package mpack

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestUintCanonicalWidths(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0xcc, 0x80}},
		{255, []byte{0xcc, 0xff}},
		{256, []byte{0xcd, 0x01, 0x00}},
		{65535, []byte{0xcd, 0xff, 0xff}},
		{65536, []byte{0xce, 0x00, 0x01, 0x00, 0x00}},
		{1 << 32, []byte{0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		got := NewEncoder(16).Uint(c.v).Bytes()
		if !bytes.Equal(got, c.want) {
			t.Errorf("Uint(%d) = % x, want % x", c.v, got, c.want)
		}
		d := NewDecoder(got)
		back, err := d.Uint()
		if err != nil {
			t.Fatalf("Uint(%d) decode: %v", c.v, err)
		}
		if back != c.v {
			t.Fatalf("Uint round trip: %d != %d", back, c.v)
		}
		if !d.Done() {
			t.Fatalf("Uint(%d) left trailing bytes", c.v)
		}
	}
}

func TestIntCanonicalWidths(t *testing.T) {
	cases := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x00}},
		{-1, []byte{0xff}},
		{-32, []byte{0xe0}},
		{-33, []byte{0xd0, 0xdf}},
		{-128, []byte{0xd0, 0x80}},
		{-129, []byte{0xd1, 0xff, 0x7f}},
		{-32768, []byte{0xd1, 0x80, 0x00}},
		{-32769, []byte{0xd2, 0xff, 0xff, 0x7f, 0xff}},
		{math.MinInt32, []byte{0xd2, 0x80, 0x00, 0x00, 0x00}},
		{math.MinInt64, []byte{0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0}},
	}
	for _, c := range cases {
		got := NewEncoder(16).Int(c.v).Bytes()
		if !bytes.Equal(got, c.want) {
			t.Errorf("Int(%d) = % x, want % x", c.v, got, c.want)
		}
		d := NewDecoder(got)
		back, err := d.Int()
		if err != nil {
			t.Fatalf("Int(%d) decode: %v", c.v, err)
		}
		if back != c.v {
			t.Fatalf("Int round trip: %d != %d", back, c.v)
		}
	}
}

func TestBinStrArray(t *testing.T) {
	enc := NewEncoder(64)
	enc.Array(3).Bin([]byte("abc")).Str("hello").Str(string(bytes.Repeat([]byte("x"), 40)))
	d := NewDecoder(enc.Bytes())
	n, err := d.Array()
	if err != nil || n != 3 {
		t.Fatalf("Array() = %d, %v", n, err)
	}
	b, err := d.Bin()
	if err != nil || string(b) != "abc" {
		t.Fatalf("Bin() = %q, %v", b, err)
	}
	s, err := d.Str()
	if err != nil || s != "hello" {
		t.Fatalf("Str() = %q, %v", s, err)
	}
	s, err = d.Str()
	if err != nil || len(s) != 40 {
		t.Fatalf("Str(long) = %d bytes, %v", len(s), err)
	}
	if !d.Done() {
		t.Fatal("trailing bytes")
	}
}

func probeAny(in []byte) error {
	probes := []func(*Decoder) error{
		func(d *Decoder) error { _, err := d.Uint(); return err },
		func(d *Decoder) error { _, err := d.Int(); return err },
		func(d *Decoder) error { _, err := d.Str(); return err },
		func(d *Decoder) error { _, err := d.Bin(); return err },
		func(d *Decoder) error { _, err := d.Array(); return err },
	}
	var first error
	for _, p := range probes {
		err := p(NewDecoder(in))
		if err == nil {
			continue
		}
		if errors.Is(err, ErrNonCanonical) {
			return err
		}
		if first == nil {
			first = err
		}
	}
	return first
}

func TestNonCanonicalRejected(t *testing.T) {
	cases := map[string][]byte{
		"uint8 for 3":     {0xcc, 0x03},
		"uint16 for 3":    {0xcd, 0x00, 0x03},
		"uint32 for 3":    {0xce, 0x00, 0x00, 0x00, 0x03},
		"int8 for -1":     {0xd0, 0xff},
		"int16 for -1":    {0xd1, 0xff, 0xff},
		"int32 for -1":    {0xd2, 0xff, 0xff, 0xff, 0xff},
		"str8 for short":  {0xd9, 0x02, 'h', 'i'},
		"str16 for short": {0xda, 0x00, 0x02, 'h', 'i'},
		"bin16 for short": {0xc5, 0x00, 0x02, 0, 0},
		"array16 for 2":   {0xdc, 0x00, 0x02, 0x00, 0x00},
		"array32 for 2":   {0xdd, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00},
	}
	for name, in := range cases {
		if err := probeAny(in); !errors.Is(err, ErrNonCanonical) {
			t.Errorf("%s: err = %v, want ErrNonCanonical", name, err)
		}
	}
}

func TestUnsupportedTypesRejected(t *testing.T) {
	for name, in := range map[string][]byte{
		"map":   {0x80},
		"float": {0xca, 0, 0, 0, 0},
		"ext":   {0xd4, 0x01, 0x00},
		"nil":   {0xc0},
	} {
		d := NewDecoder(in)
		if _, err := d.Uint(); err == nil {
			t.Errorf("%s: expected a type error", name)
		}
	}
}

func TestTruncatedRejected(t *testing.T) {
	enc := NewEncoder(64)
	enc.Array(2).Bin([]byte("abcdef")).Uint(300)
	full := enc.Bytes()
	for cut := 1; cut < len(full); cut++ {
		d := NewDecoder(full[:cut])
		if _, err := d.Array(); err != nil {
			continue
		}
		if _, err := d.Bin(); err != nil {
			continue
		}
		if _, err := d.Uint(); err == nil {
			t.Fatalf("truncated at %d: expected an error", cut)
		}
	}
}

func TestNegativeUintRejected(t *testing.T) {
	d := NewDecoder([]byte{0xff})
	if _, err := d.Uint(); !errors.Is(err, ErrNegative) {
		t.Fatalf("err = %v, want ErrNegative", err)
	}
}

func TestRandomInputNeverPanics(t *testing.T) {
	seed := uint64(0x9e3779b97f4a7c15)
	next := func() byte {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return byte(seed)
	}
	buf := make([]byte, 64)
	for i := 0; i < 20000; i++ {
		n := int(next())%len(buf) + 1
		for j := 0; j < n; j++ {
			buf[j] = next()
		}
		d := NewDecoder(buf[:n])
		for k := 0; k < 8 && !d.Done(); k++ {
			switch next() % 5 {
			case 0:
				_, _ = d.Uint()
			case 1:
				_, _ = d.Int()
			case 2:
				_, _ = d.Bin()
			case 3:
				_, _ = d.Str()
			case 4:
				_, _ = d.Array()
			}
		}
	}
}
