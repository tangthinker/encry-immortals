// Package codec is eimmortal's single compression entry point (spec §3.4, D-11).
//
// Rules that the rest of the system relies on:
//   - Compression always happens *before* encryption, never after.
//   - The codec byte and the pre-compression length both enter the AAD, so
//     decompression must be told the exact expected length.
//   - Incompressible inputs (already-compressed media, ciphertext) stay codec=none
//     so we never burn CPU for ~1% gain.
//
// The zstd frame CRC is disabled on purpose: every slice is already covered by
// Poly1305 and by plain_sha256 in the journal, so a second checksum only costs
// bytes and CPU.
package codec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Codec identifiers as they appear on the wire (spec §3.3).
const (
	None byte = 0
	Zstd byte = 1
)

// Compression parameters. Level follows the zstd scale (1 fastest .. 22 best);
// spec §3.4 pins the default to 5.
const (
	DefaultLevel      = 5
	MinLevel          = 1
	MaxLevel          = 22
	DefaultMinBytes   = 4096
	DefaultProbeBytes = 64 << 10
	DefaultProbeRatio = 0.98
	// MinCompressBytes is kept for callers/tests that used the old constant.
	MinCompressBytes = DefaultMinBytes
	// ProbeBytes / ProbeRatioThreshold are kept for documentation purposes.
	ProbeBytes          = DefaultProbeBytes
	ProbeRatioThreshold = DefaultProbeRatio
)

// ErrInvalidCodec is returned for wire values outside {None, Zstd}.
var ErrInvalidCodec = errors.New("codec: unknown codec id")

// Options tunes compression. Zero values fall back to the defaults.
type Options struct {
	// Level is the zstd level, clamped to [MinLevel, MaxLevel].
	Level int
	// MinBytes is the size below which a slice is stored uncompressed.
	MinBytes int
	// ProbeBytes is how much of a large slice is sampled to detect
	// incompressible data (0 disables probing).
	ProbeBytes int
	// ProbeRatio is the compressed/probe ratio above which a slice is stored
	// uncompressed.
	ProbeRatio float64
}

// DefaultOptions returns the spec defaults.
func DefaultOptions() Options {
	return Options{
		Level:      DefaultLevel,
		MinBytes:   DefaultMinBytes,
		ProbeBytes: DefaultProbeBytes,
		ProbeRatio: DefaultProbeRatio,
	}
}

// Normalized clamps out-of-range values.
func (o Options) Normalized() Options {
	if o.Level == 0 {
		o.Level = DefaultLevel
	}
	if o.Level < MinLevel {
		o.Level = MinLevel
	}
	if o.Level > MaxLevel {
		o.Level = MaxLevel
	}
	if o.MinBytes < 0 {
		o.MinBytes = DefaultMinBytes
	}
	if o.ProbeBytes < 0 {
		o.ProbeBytes = DefaultProbeBytes
	}
	if o.ProbeBytes == 0 {
		o.ProbeBytes = DefaultProbeBytes
	}
	if o.ProbeRatio <= 0 || o.ProbeRatio > 1 {
		o.ProbeRatio = DefaultProbeRatio
	}
	return o
}

var encoderPools sync.Map // int -> *sync.Pool

func encoderPool(level int) *sync.Pool {
	if p, ok := encoderPools.Load(level); ok {
		return p.(*sync.Pool)
	}
	p := &sync.Pool{}
	p.New = func() any {
		w, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderCRC(false),
		)
		if err != nil {
			panic("codec: zstd encoder: " + err.Error())
		}
		return w
	}
	actual, _ := encoderPools.LoadOrStore(level, p)
	return actual.(*sync.Pool)
}

// Compress uses the default options (kept for callers that need no tuning).
func Compress(src []byte) (byte, []byte, error) {
	return CompressWith(src, DefaultOptions())
}

// CompressWith returns the codec id and the bytes to encrypt.
//
// When the result is not smaller than the input, when the input is below
// o.MinBytes, or when the probe says the data is incompressible, the returned id
// is None and out aliases src.
func CompressWith(src []byte, o Options) (byte, []byte, error) {
	o = o.Normalized()
	if len(src) < o.MinBytes {
		return None, src, nil
	}
	if o.ProbeBytes > 0 && len(src) > o.ProbeBytes {
		probe := src[:o.ProbeBytes]
		enc := encoderPool(o.Level).Get().(*zstd.Encoder)
		out := enc.EncodeAll(probe, nil)
		encoderPool(o.Level).Put(enc)
		if float64(len(out))/float64(len(probe)) > o.ProbeRatio {
			return None, src, nil
		}
	}
	enc := encoderPool(o.Level).Get().(*zstd.Encoder)
	out := enc.EncodeAll(src, nil)
	encoderPool(o.Level).Put(enc)
	if len(out) >= len(src) {
		return None, src, nil
	}
	return Zstd, out, nil
}

// Decompress decodes src according to id.
//
// maxLen is the pre-compression plaintext length taken from the envelope header;
// it is mandatory for Zstd (bomb protection) and must match the output exactly.
// The caller is responsible for the exact-length check because it also covers
// the None case.
func Decompress(id byte, src []byte, maxLen int) ([]byte, error) {
	switch id {
	case None:
		if maxLen > 0 && len(src) > maxLen {
			return nil, fmt.Errorf("codec: plaintext length %d exceeds declared %d", len(src), maxLen)
		}
		return src, nil
	case Zstd:
		if maxLen <= 0 {
			return nil, errors.New("codec: zstd requires a positive declared plaintext length")
		}
		// zstd requires a window of at least 1 KiB; slices may be smaller when
		// min_compress_bytes is lowered, so clamp instead of failing.
		limit := uint64(maxLen)
		if limit < 1<<10 {
			limit = 1 << 10
		}
		r, err := zstd.NewReader(bytes.NewReader(src),
			zstd.WithDecoderMaxMemory(limit),
			zstd.WithDecoderMaxWindow(limit),
			zstd.WithDecoderConcurrency(1),
		)
		if err != nil {
			return nil, fmt.Errorf("codec: zstd decoder: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, int64(maxLen)+1))
		if err != nil {
			return nil, fmt.Errorf("codec: zstd decompress: %w", err)
		}
		if len(out) > maxLen {
			return nil, fmt.Errorf("codec: decompressed %d bytes exceeds declared %d", len(out), maxLen)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidCodec, id)
	}
}
