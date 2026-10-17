// Package mpack is a deliberately small, canonical MessagePack codec.
//
// Spec §04.2 / ADR-004 requires a positional array schema with:
//   - shortest possible integer encoding,
//   - no floats, no maps, no ext types,
//   - byte-stable output across implementations (golden vectors depend on it).
//
// The decoder therefore rejects non-canonical encodings (e.g. a uint16 holding
// 3) instead of accepting them, so any wire bytes can only be produced in
// exactly one way.
package mpack

import (
	"errors"
	"fmt"
	"math"
)

// Sentinel errors. All decode errors wrap one of them so callers can decide
// between "data is corrupt" (E12) and "data is truncated" (E13).
var (
	ErrTruncated    = errors.New("mpack: truncated input")
	ErrNonCanonical = errors.New("mpack: non-canonical encoding")
	ErrType         = errors.New("mpack: unexpected type")
	ErrNegative     = errors.New("mpack: negative value where unsigned was required")
)

// Encoder appends canonical MessagePack values to an internal buffer.
type Encoder struct {
	b []byte
}

// NewEncoder returns an encoder with the given initial capacity.
func NewEncoder(capacity int) *Encoder {
	return &Encoder{b: make([]byte, 0, capacity)}
}

// Bytes returns the encoded buffer. The caller must not modify it afterwards.
func (e *Encoder) Bytes() []byte { return e.b }

// Len reports the number of encoded bytes.
func (e *Encoder) Len() int { return len(e.b) }

// Nil encodes nil.
func (e *Encoder) Nil() *Encoder { e.b = append(e.b, 0xc0); return e }

// Bool encodes a boolean.
func (e *Encoder) Bool(v bool) *Encoder {
	if v {
		e.b = append(e.b, 0xc3)
	} else {
		e.b = append(e.b, 0xc2)
	}
	return e
}

// Uint encodes a non-negative integer in its shortest form.
func (e *Encoder) Uint(v uint64) *Encoder {
	switch {
	case v <= 0x7f:
		e.b = append(e.b, byte(v))
	case v <= math.MaxUint8:
		e.b = append(e.b, 0xcc, byte(v))
	case v <= math.MaxUint16:
		e.b = append(e.b, 0xcd, byte(v>>8), byte(v))
	case v <= math.MaxUint32:
		e.b = append(e.b, 0xce, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		e.b = append(e.b, 0xcf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return e
}

// Int encodes a signed integer in its shortest form. Non-negative values are
// encoded exactly as Uint so the representation stays unique.
func (e *Encoder) Int(v int64) *Encoder {
	if v >= 0 {
		return e.Uint(uint64(v))
	}
	switch {
	case v >= -32:
		e.b = append(e.b, byte(int8(v)))
	case v >= math.MinInt8:
		e.b = append(e.b, 0xd0, byte(v))
	case v >= math.MinInt16:
		e.b = append(e.b, 0xd1, byte(v>>8), byte(v))
	case v >= math.MinInt32:
		e.b = append(e.b, 0xd2, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		e.b = append(e.b, 0xd3, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return e
}

// Bin encodes a byte string.
func (e *Encoder) Bin(v []byte) *Encoder {
	n := len(v)
	switch {
	case n <= math.MaxUint8:
		e.b = append(e.b, 0xc4, byte(n))
	case n <= math.MaxUint16:
		e.b = append(e.b, 0xc5, byte(n>>8), byte(n))
	default:
		e.b = append(e.b, 0xc6, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	e.b = append(e.b, v...)
	return e
}

// Str encodes a UTF-8 string.
func (e *Encoder) Str(v string) *Encoder {
	n := len(v)
	switch {
	case n <= 31:
		e.b = append(e.b, 0xa0|byte(n))
	case n <= math.MaxUint8:
		e.b = append(e.b, 0xd9, byte(n))
	case n <= math.MaxUint16:
		e.b = append(e.b, 0xda, byte(n>>8), byte(n))
	default:
		e.b = append(e.b, 0xdb, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	e.b = append(e.b, v...)
	return e
}

// Array begins an array of n elements; the caller must encode exactly n values.
func (e *Encoder) Array(n int) *Encoder {
	switch {
	case n <= 15:
		e.b = append(e.b, 0x90|byte(n))
	case n <= math.MaxUint16:
		e.b = append(e.b, 0xdc, byte(n>>8), byte(n))
	default:
		e.b = append(e.b, 0xdd, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return e
}

// Decoder reads canonical MessagePack from a byte slice.
type Decoder struct {
	b   []byte
	off int
}

// NewDecoder wraps b.
func NewDecoder(b []byte) *Decoder { return &Decoder{b: b} }

// Remaining reports how many bytes are left.
func (d *Decoder) Remaining() int { return len(d.b) - d.off }

// Done reports whether the input has been fully consumed.
func (d *Decoder) Done() bool { return d.off == len(d.b) }

// ErrTrailing is returned when the caller consumed less than the whole input.
func (d *Decoder) ErrTrailing() error {
	if d.Done() {
		return nil
	}
	return fmt.Errorf("mpack: %d trailing bytes", d.Remaining())
}

func truncated(what string) error {
	return fmt.Errorf("%w: %s", ErrTruncated, what)
}

func nonCanonical(what string) error {
	return fmt.Errorf("%w: %s", ErrNonCanonical, what)
}

func typeErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrType, fmt.Sprintf(format, args...))
}

func (d *Decoder) byte() (byte, error) {
	if d.off >= len(d.b) {
		return 0, truncated("byte")
	}
	v := d.b[d.off]
	d.off++
	return v, nil
}

func (d *Decoder) peek() (byte, error) {
	if d.off >= len(d.b) {
		return 0, truncated("byte")
	}
	return d.b[d.off], nil
}

func (d *Decoder) take(n int) ([]byte, error) {
	if n < 0 || d.off+n > len(d.b) {
		return nil, truncated(fmt.Sprintf("%d bytes", n))
	}
	v := d.b[d.off : d.off+n]
	d.off += n
	return v, nil
}

func (d *Decoder) uintN(n int) (uint64, error) {
	b, err := d.take(n)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// Nil consumes a nil.
func (d *Decoder) Nil() error {
	b, err := d.byte()
	if err != nil {
		return err
	}
	if b != 0xc0 {
		d.off--
		return typeErr("expected nil, got 0x%02x", b)
	}
	return nil
}

// Bool consumes a boolean.
func (d *Decoder) Bool() (bool, error) {
	b, err := d.byte()
	if err != nil {
		return false, err
	}
	switch b {
	case 0xc2:
		return false, nil
	case 0xc3:
		return true, nil
	}
	d.off--
	return false, typeErr("expected bool, got 0x%02x", b)
}

// Uint consumes a non-negative integer.
func (d *Decoder) Uint() (uint64, error) {
	v, err := d.integer()
	if err != nil {
		return 0, err
	}
	if v.neg {
		return 0, fmt.Errorf("%w: %d", ErrNegative, v.mag)
	}
	return v.mag, nil
}

// Int consumes any integer.
func (d *Decoder) Int() (int64, error) {
	v, err := d.integer()
	if err != nil {
		return 0, err
	}
	if !v.neg {
		if v.mag > math.MaxInt64 {
			return 0, typeErr("integer out of int64 range")
		}
		return int64(v.mag), nil
	}
	if v.mag > 1<<63 {
		return 0, typeErr("integer out of int64 range")
	}
	if v.mag == 1<<63 {
		return math.MinInt64, nil
	}
	return -int64(v.mag), nil
}

type integer struct {
	mag uint64 // absolute value
	neg bool
}

func (d *Decoder) integer() (integer, error) {
	b, err := d.byte()
	if err != nil {
		return integer{}, err
	}
	switch {
	case b <= 0x7f:
		return integer{mag: uint64(b)}, nil
	case b >= 0xe0:
		return integer{mag: uint64(256 - int(b)), neg: true}, nil
	}
	switch b {
	case 0xcc:
		v, err := d.uintN(1)
		if err != nil {
			return integer{}, err
		}
		if v < 0x80 {
			return integer{}, nonCanonical("uint8 below 128")
		}
		return integer{mag: v}, nil
	case 0xcd:
		v, err := d.uintN(2)
		if err != nil {
			return integer{}, err
		}
		if v < 0x100 {
			return integer{}, nonCanonical("uint16 below 256")
		}
		return integer{mag: v}, nil
	case 0xce:
		v, err := d.uintN(4)
		if err != nil {
			return integer{}, err
		}
		if v < 0x10000 {
			return integer{}, nonCanonical("uint32 below 65536")
		}
		return integer{mag: v}, nil
	case 0xcf:
		v, err := d.uintN(8)
		if err != nil {
			return integer{}, err
		}
		if v < 1<<32 {
			return integer{}, nonCanonical("uint64 below 2^32")
		}
		return integer{mag: v}, nil
	case 0xd0:
		raw, err := d.uintN(1)
		if err != nil {
			return integer{}, err
		}
		i := int64(int8(byte(raw)))
		if i >= -32 {
			return integer{}, nonCanonical("int8 above -32")
		}
		return integer{mag: uint64(-i), neg: true}, nil
	case 0xd1:
		raw, err := d.uintN(2)
		if err != nil {
			return integer{}, err
		}
		i := int64(int16(raw))
		if i >= -128 {
			return integer{}, nonCanonical("int16 above -128")
		}
		return integer{mag: uint64(-i), neg: true}, nil
	case 0xd2:
		raw, err := d.uintN(4)
		if err != nil {
			return integer{}, err
		}
		i := int64(int32(raw))
		if i >= -32768 {
			return integer{}, nonCanonical("int32 above -32768")
		}
		return integer{mag: uint64(-i), neg: true}, nil
	case 0xd3:
		raw, err := d.uintN(8)
		if err != nil {
			return integer{}, err
		}
		i := int64(raw)
		if i >= -2147483648 {
			return integer{}, nonCanonical("int64 above -2^31")
		}
		if i == math.MinInt64 {
			return integer{mag: 1 << 63, neg: true}, nil
		}
		return integer{mag: uint64(-i), neg: true}, nil
	}
	d.off--
	return integer{}, typeErr("expected integer, got 0x%02x", b)
}

// Bin consumes a byte string. The returned slice aliases the decoder input.
func (d *Decoder) Bin() ([]byte, error) {
	b, err := d.byte()
	if err != nil {
		return nil, err
	}
	var n uint64
	switch b {
	case 0xc4:
		n, err = d.uintN(1)
	case 0xc5:
		n, err = d.uintN(2)
		if err == nil && n < 0x100 {
			return nil, nonCanonical("bin16 below 256")
		}
	case 0xc6:
		n, err = d.uintN(4)
		if err == nil && n < 0x10000 {
			return nil, nonCanonical("bin32 below 65536")
		}
	default:
		d.off--
		return nil, typeErr("expected bin, got 0x%02x", b)
	}
	if err != nil {
		return nil, err
	}
	if n > uint64(d.Remaining()) {
		return nil, truncated("bin payload")
	}
	return d.take(int(n))
}

// Str consumes a UTF-8 string.
func (d *Decoder) Str() (string, error) {
	b, err := d.byte()
	if err != nil {
		return "", err
	}
	var n uint64
	switch {
	case b >= 0xa0 && b <= 0xbf:
		n = uint64(b & 0x1f)
	case b == 0xd9:
		n, err = d.uintN(1)
		if err == nil && n < 32 {
			return "", nonCanonical("str8 below 32")
		}
	case b == 0xda:
		n, err = d.uintN(2)
		if err == nil && n < 0x100 {
			return "", nonCanonical("str16 below 256")
		}
	case b == 0xdb:
		n, err = d.uintN(4)
		if err == nil && n < 0x10000 {
			return "", nonCanonical("str32 below 65536")
		}
	default:
		d.off--
		return "", typeErr("expected str, got 0x%02x", b)
	}
	if err != nil {
		return "", err
	}
	if n > uint64(d.Remaining()) {
		return "", truncated("str payload")
	}
	raw, err := d.take(int(n))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Array consumes an array header and returns its element count.
func (d *Decoder) Array() (int, error) {
	b, err := d.byte()
	if err != nil {
		return 0, err
	}
	var n uint64
	switch {
	case b >= 0x90 && b <= 0x9f:
		n = uint64(b & 0x0f)
	case b == 0xdc:
		n, err = d.uintN(2)
		if err == nil && n < 16 {
			return 0, nonCanonical("array16 below 16")
		}
	case b == 0xdd:
		n, err = d.uintN(4)
		if err == nil && n < 0x10000 {
			return 0, nonCanonical("array32 below 65536")
		}
	default:
		d.off--
		return 0, typeErr("expected array, got 0x%02x", b)
	}
	if err != nil {
		return 0, err
	}
	if n > uint64(d.Remaining()) {
		// every element needs at least one byte
		return 0, truncated("array elements")
	}
	return int(n), nil
}
