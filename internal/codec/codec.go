// Package codec is apex's single compression entry point (spec §3.4, D-11).
//
// Rules that the rest of the system relies on:
//   - Compression always happens *before* encryption, never after.
//   - The codec byte and the pre-compression length both enter the AAD, so
//     decompression must be told the exact expected length.
//   - Incompressible inputs (already-compressed media, ciphertext) stay codec=none
//     so we never burn 3x CPU for 1% gain.
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

const (
	// MinCompressBytes is the threshold below which compression is skipped (§3.4).
	MinCompressBytes = 4096
	// ProbeBytes is how much of a large slice is compressed to estimate the ratio.
	ProbeBytes = 64 << 10
	// ProbeRatioThreshold: above this ratio the slice is stored uncompressed.
	ProbeRatioThreshold = 0.98
	// Level is the zstd level required by §3.4.
	Level = 5
)

// ErrInvalidCodec is returned for wire values outside {None, Zstd}.
var ErrInvalidCodec = errors.New("codec: unknown codec id")

var encPool = sync.Pool{
	New: func() any {
		w, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(Level)),
			zstd.WithEncoderConcurrency(1),
		)
		if err != nil {
			panic("codec: zstd encoder: " + err.Error())
		}
		return w
	},
}

// Compress returns the codec id and the bytes to encrypt.
//
// When the result is not smaller than the input, or when the input is small or
// clearly incompressible, the returned id is None and out aliases src.
func Compress(src []byte) (byte, []byte, error) {
	if len(src) < MinCompressBytes {
		return None, src, nil
	}
	if len(src) > ProbeBytes {
		probe := src[:ProbeBytes]
		enc := encPool.Get().(*zstd.Encoder)
		out := enc.EncodeAll(probe, nil)
		encPool.Put(enc)
		if float64(len(out))/float64(len(probe)) > ProbeRatioThreshold {
			return None, src, nil
		}
	}
	enc := encPool.Get().(*zstd.Encoder)
	out := enc.EncodeAll(src, nil)
	encPool.Put(enc)
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
		r, err := zstd.NewReader(bytes.NewReader(src),
			zstd.WithDecoderMaxMemory(uint64(maxLen)),
			zstd.WithDecoderMaxWindow(uint64(maxLen)),
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
