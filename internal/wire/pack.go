package wire

import (
	"encoding/binary"
	"fmt"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
)

// Pack layout constants (spec §03.2).
const (
	// PackHeaderSize is fixed at 32 bytes.
	PackHeaderSize = 32
	// PackFlagHasFooter marks a pack that carries a footer.
	PackFlagHasFooter byte = 0x01
	// packHeaderPadLen keeps the header fully random after byte 24.
	packHeaderPadLen = 8
)

// PackHeader is the plaintext 32-byte pack prefix.
type PackHeader struct {
	PackID      []byte // 16 random bytes, part of every slice AAD
	VerAlg      byte
	Flags       byte
	CreatedUnix uint32
	Padding     []byte // 8 random bytes
}

// NewPackHeader generates a fresh pack id and random padding.
func NewPackHeader(createdUnix int64) (*PackHeader, error) {
	id, err := vaultcrypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	pad, err := vaultcrypto.RandomBytes(packHeaderPadLen)
	if err != nil {
		return nil, err
	}
	return &PackHeader{
		PackID:      id,
		VerAlg:      vaultcrypto.VerAlg,
		CreatedUnix: uint32(createdUnix),
		Padding:     pad,
	}, nil
}

// Encode renders the header as exactly 32 bytes.
func (h *PackHeader) Encode() ([]byte, error) {
	if len(h.PackID) != 16 {
		return nil, fmt.Errorf("wire: pack_id must be 16 bytes, got %d", len(h.PackID))
	}
	if len(h.Padding) != packHeaderPadLen {
		return nil, fmt.Errorf("wire: pack padding must be %d bytes", packHeaderPadLen)
	}
	out := make([]byte, 0, PackHeaderSize)
	out = append(out, h.PackID...)
	out = append(out, h.VerAlg, h.Flags, 0x00, 0x00)
	out = binary.BigEndian.AppendUint32(out, h.CreatedUnix)
	out = append(out, h.Padding...)
	return out, nil
}

// ParsePackHeader validates a 32-byte pack header.
func ParsePackHeader(b []byte) (*PackHeader, error) {
	if len(b) < PackHeaderSize {
		return nil, corrupt("pack 头过短：%d 字节（至少 %d）", len(b), PackHeaderSize)
	}
	h := &PackHeader{
		PackID:      append([]byte(nil), b[0:16]...),
		VerAlg:      b[16],
		Flags:       b[17],
		CreatedUnix: binary.BigEndian.Uint32(b[20:24]),
		Padding:     append([]byte(nil), b[24:32]...),
	}
	if h.VerAlg != vaultcrypto.VerAlg {
		return nil, corrupt("pack 头版本/算法不受支持：ver_alg=0x%02x", h.VerAlg)
	}
	if h.Flags&^PackFlagHasFooter != 0 {
		return nil, corrupt("pack 头包含未知 flags 位：0x%02x", h.Flags)
	}
	if binary.BigEndian.Uint16(b[18:20]) != 0 {
		return nil, corrupt("pack 头 reserved 字段非零")
	}
	return h, nil
}

// FooterEntry is one slice descriptor inside a pack footer (§03.2).
type FooterEntry struct {
	Offset   uint64
	EnvLen   uint32
	PlainLen uint32
	Index    uint32
}

// footerEntrySize = u64 + u32 + u32 + u32.
const footerEntrySize = 20

// SealFooter encrypts the footer for a pack whose slices end at footerStart.
// The returned bytes are body||tail and must be appended at footerStart.
func SealFooter(storageKey, packID []byte, footerStart uint64, entries []FooterEntry) ([]byte, error) {
	nonce, err := vaultcrypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	return SealFooterWithNonce(storageKey, packID, footerStart, entries, nonce)
}

// SealFooterWithNonce is SealFooter with a fixed nonce (golden vectors/tests).
func SealFooterWithNonce(storageKey, packID []byte, footerStart uint64, entries []FooterEntry, nonce []byte) ([]byte, error) {
	if len(nonce) != vaultcrypto.NonceLen {
		return nil, fmt.Errorf("wire: nonce must be %d bytes", vaultcrypto.NonceLen)
	}
	plain := make([]byte, 0, 1+4+len(entries)*footerEntrySize)
	plain = append(plain, vaultcrypto.VerAlg)
	plain = binary.BigEndian.AppendUint32(plain, uint32(len(entries)))
	for _, e := range entries {
		plain = binary.BigEndian.AppendUint64(plain, e.Offset)
		plain = binary.BigEndian.AppendUint32(plain, e.EnvLen)
		plain = binary.BigEndian.AppendUint32(plain, e.PlainLen)
		plain = binary.BigEndian.AppendUint32(plain, e.Index)
	}
	aad, err := vaultcrypto.FooterAAD(vaultcrypto.VerAlg, packID, footerStart)
	if err != nil {
		return nil, err
	}
	ct, err := vaultcrypto.Seal(storageKey, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, vaultcrypto.NonceLen+len(ct)+4)
	body = append(body, nonce...)
	body = append(body, ct...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(body)+4))
	return body, nil
}

// LocateFooter implements the mandatory footer locator (spec §03.2): it uses the
// file size and the last 4 bytes, and refuses anything that could be a truncated
// tail pretending to be a valid footer.
func LocateFooter(size int64, last4 []byte) (start uint64, length uint32, err error) {
	if len(last4) != 4 {
		return 0, 0, corrupt("footer 定位需要文件最后 4 字节")
	}
	if size < PackHeaderSize+4 {
		return 0, 0, corrupt("pack 文件过短：%d 字节", size)
	}
	l := binary.BigEndian.Uint32(last4)
	if l < 44 {
		return 0, 0, corrupt("footer 长度 %d 小于下限 44", l)
	}
	if int64(l) > size-PackHeaderSize {
		return 0, 0, corrupt("footer 长度 %d 超过文件可容纳范围（size=%d）", l, size)
	}
	return uint64(size) - uint64(l), l, nil
}

// OpenFooter decrypts and validates a footer. raw is the full footer
// (body||tail) starting at footerStart.
func OpenFooter(storageKey, packID []byte, footerStart uint64, raw []byte) ([]FooterEntry, error) {
	if len(raw) < vaultcrypto.NonceLen+1+vaultcrypto.TagLen+4 {
		return nil, corrupt("footer 过短：%d 字节", len(raw))
	}
	if tail := binary.BigEndian.Uint32(raw[len(raw)-4:]); int(tail) != len(raw) {
		return nil, corrupt("footer 尾部长度字段 %d 与实际 %d 不一致", tail, len(raw))
	}
	body := raw[:len(raw)-4]
	nonce := body[:vaultcrypto.NonceLen]
	ct := body[vaultcrypto.NonceLen:]
	aad, err := vaultcrypto.FooterAAD(vaultcrypto.VerAlg, packID, footerStart)
	if err != nil {
		return nil, err
	}
	pt, err := vaultcrypto.Open(storageKey, nonce, ct, aad)
	if err != nil {
		return nil, corrupt("footer 解密失败（可能被截断）").WithErr(err)
	}
	if len(pt) < 5 || pt[0] != vaultcrypto.VerAlg {
		return nil, corrupt("footer 明文头非法")
	}
	count := binary.BigEndian.Uint32(pt[1:5])
	if uint64(len(pt)) != 5+uint64(count)*footerEntrySize {
		return nil, corrupt("footer 条目数 %d 与长度 %d 不一致", count, len(pt))
	}
	entries := make([]FooterEntry, 0, count)
	off := 5
	for i := uint32(0); i < count; i++ {
		e := FooterEntry{
			Offset:   binary.BigEndian.Uint64(pt[off : off+8]),
			EnvLen:   binary.BigEndian.Uint32(pt[off+8 : off+12]),
			PlainLen: binary.BigEndian.Uint32(pt[off+12 : off+16]),
			Index:    binary.BigEndian.Uint32(pt[off+16 : off+20]),
		}
		entries = append(entries, e)
		off += footerEntrySize
	}
	return entries, nil
}

var _ = apexerr.New
