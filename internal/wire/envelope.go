// Package wire implements APEX's on-disk byte formats:
// slice envelopes, pack headers/footers and journal bodies (spec 03 / 04).
//
// Everything in this package is byte-level and side-effect free; the storage
// layer owns files, offsets and durability.
package wire

import (
	"encoding/binary"
	"fmt"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
)

// Slice envelope layout (spec §03.3).
const (
	// EnvelopeHeaderSize = ver_alg(1) + env_len(4) + plain_len(4) + codec(1) + nonce(24).
	EnvelopeHeaderSize = 34
	// EnvelopeTagSize is the Poly1305 tag.
	EnvelopeTagSize = 16
	// EnvelopeMinLen = 50, the smallest legal envelope.
	EnvelopeMinLen = EnvelopeHeaderSize + EnvelopeTagSize

	// DefaultSlicePlain is the policy default for slice_plain_bytes (spec §03.6).
	DefaultSlicePlain = 32 << 20
	// MaxSlicePlainHard is the absolute wire ceiling for plain_len. Larger values
	// cannot be parsed at all; the store layer enforces the configured (smaller)
	// slice_plain_bytes on top of this.
	MaxSlicePlainHard = 64 << 20
	// maxCompressedLen is the zstd worst-case upper bound from spec §03.6.
	maxCompressedLen = MaxSlicePlainHard + MaxSlicePlainHard/128 + 256
)

func corrupt(format string, args ...any) *apexerr.Error {
	return apexerr.Newf(apexerr.CodeCorrupt, format, args...)
}

// SliceHeader is the parsed, authenticated part of a slice envelope.
type SliceHeader struct {
	VerAlg   byte
	EnvLen   uint32
	PlainLen uint32
	Codec    byte
	Nonce    []byte
}

// ParseSliceHeader validates and parses an envelope header from env, which must
// start at the envelope's first byte.
func ParseSliceHeader(env []byte) (SliceHeader, error) {
	var h SliceHeader
	if len(env) < EnvelopeMinLen {
		return h, corrupt("切片信封过短：%d 字节（至少 %d）", len(env), EnvelopeMinLen)
	}
	h.VerAlg = env[0]
	if h.VerAlg != vaultcrypto.VerAlg {
		return h, corrupt("切片信封版本/算法不受支持：ver_alg=0x%02x", h.VerAlg)
	}
	h.EnvLen = binary.BigEndian.Uint32(env[1:5])
	h.PlainLen = binary.BigEndian.Uint32(env[5:9])
	h.Codec = env[9]
	if h.EnvLen != uint32(len(env)) {
		return h, corrupt("切片信封长度字段 %d 与实际 %d 不一致", h.EnvLen, len(env))
	}
	if h.EnvLen < EnvelopeMinLen || h.EnvLen > EnvelopeMinLen+maxCompressedLen {
		return h, corrupt("切片信封长度 %d 超出允许范围", h.EnvLen)
	}
	if h.PlainLen > MaxSlicePlainHard {
		return h, corrupt("切片明文长度 %d 超过上限 %d（解密前拒绝）", h.PlainLen, MaxSlicePlainHard)
	}
	if h.Codec != codec.None && h.Codec != codec.Zstd {
		return h, corrupt("切片 codec 非法：%d", h.Codec)
	}
	if h.Codec == codec.None && h.PlainLen != h.EnvLen-EnvelopeMinLen {
		return h, corrupt("切片 codec=none 但 plain_len=%d 与密文长度 %d 不一致", h.PlainLen, h.EnvLen-EnvelopeMinLen)
	}
	h.Nonce = env[10:EnvelopeHeaderSize]
	return h, nil
}

// SealSlice produces one envelope bound to (packID, offset, index, txnID).
//
// plainLen is the pre-compression length, payload is the (possibly compressed)
// plaintext to encrypt. Production code must use this function; tests and
// golden vectors use SealSliceWithNonce.
func SealSlice(key []byte, codecID byte, plainLen int, payload []byte, packID []byte, offset uint64, index uint32, txnID []byte) ([]byte, error) {
	nonce, err := vaultcrypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	return SealSliceWithNonce(key, codecID, plainLen, payload, packID, offset, index, txnID, nonce)
}

// SealSliceWithNonce is SealSlice with a caller-supplied nonce. Production code
// must never pass a reused nonce (I18); only golden vectors and tests use it.
func SealSliceWithNonce(key []byte, codecID byte, plainLen int, payload []byte, packID []byte, offset uint64, index uint32, txnID []byte, nonce []byte) ([]byte, error) {
	if codecID != codec.None && codecID != codec.Zstd {
		return nil, fmt.Errorf("wire: invalid codec id %d", codecID)
	}
	if plainLen < 0 || plainLen > MaxSlicePlainHard {
		return nil, fmt.Errorf("wire: plain_len %d out of range", plainLen)
	}
	if codecID == codec.None && len(payload) != plainLen {
		return nil, fmt.Errorf("wire: codec=none requires len(payload)==plain_len (%d != %d)", len(payload), plainLen)
	}
	if len(nonce) != vaultcrypto.NonceLen {
		return nil, fmt.Errorf("wire: nonce must be %d bytes", vaultcrypto.NonceLen)
	}
	envLen := EnvelopeMinLen + len(payload)
	if envLen > EnvelopeMinLen+maxCompressedLen {
		return nil, fmt.Errorf("wire: envelope length %d out of range", envLen)
	}
	aad, err := vaultcrypto.SliceAAD(vaultcrypto.VerAlg, codecID, uint32(envLen), uint32(plainLen), packID, offset, index, txnID)
	if err != nil {
		return nil, err
	}
	ct, err := vaultcrypto.Seal(key, nonce, payload, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, envLen)
	out = append(out, vaultcrypto.VerAlg)
	out = binary.BigEndian.AppendUint32(out, uint32(envLen))
	out = binary.BigEndian.AppendUint32(out, uint32(plainLen))
	out = append(out, codecID)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenSlice authenticates and decrypts one envelope.
//
// packID, offset, index and txnID must come from the reader's actual position
// (journal index + seek), never from the envelope itself: that binding is what
// makes slice relocation and reordering detectable (I3).
func OpenSlice(key, env, packID []byte, offset uint64, index uint32, txnID []byte) (payload []byte, codecID byte, plainLen int, err error) {
	h, err := ParseSliceHeader(env)
	if err != nil {
		return nil, 0, 0, err
	}
	aad, err := vaultcrypto.SliceAAD(h.VerAlg, h.Codec, h.EnvLen, h.PlainLen, packID, offset, index, txnID)
	if err != nil {
		return nil, 0, 0, err
	}
	ct := env[EnvelopeHeaderSize:]
	pt, err := vaultcrypto.Open(key, h.Nonce, ct, aad)
	if err != nil {
		return nil, 0, 0, corrupt("切片解密失败（MAC 校验不通过）").
			WithErr(err).
			WithNext("确认该 pack 未被云端截断或改写；必要时执行 apex verify --deep")
	}
	if int(h.PlainLen) > 0 && h.Codec == codec.Zstd {
		// decompression is the caller's job; the declared length is returned
	}
	return pt, h.Codec, int(h.PlainLen), nil
}
