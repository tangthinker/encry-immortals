package store

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// PackReader reads slices back, verifying size, AEAD, codec and plaintext hash
// (invariant I7). Handles are cached per relative pack name.
type PackReader struct {
	layout *Layout
	key    []byte
	open   map[string]*packHandle
}

type packHandle struct {
	rel    string
	f      *os.File
	size   int64
	header *wire.PackHeader
}

// NewPackReader builds a reader over one TargetDir.
func NewPackReader(layout *Layout, storageKey []byte) (*PackReader, error) {
	if len(storageKey) != vaultcrypto.KeyLen {
		return nil, apexerr.Newf(apexerr.CodeUsage, "内部错误：storage key 长度 %d", len(storageKey))
	}
	return &PackReader{layout: layout, key: storageKey, open: make(map[string]*packHandle)}, nil
}

// Close releases every open pack handle.
func (r *PackReader) Close() error {
	var first error
	for name, h := range r.open {
		if err := h.f.Close(); err != nil && first == nil {
			first = err
		}
		delete(r.open, name)
	}
	return first
}

// Open resolves and validates a pack. expectSize is the size recorded in the
// journal; a mismatch means the pack is still syncing or was truncated (E13,
// spec 06.6).
func (r *PackReader) Open(rel string, expectSize uint64) (*packHandle, error) {
	if h, ok := r.open[rel]; ok {
		if expectSize > 0 && uint64(h.size) != expectSize {
			return nil, r.sizeMismatch(rel, h.size, expectSize)
		}
		return h, nil
	}
	abs, err := r.layout.AbsPath(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Clean(abs))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apexerr.Newf(apexerr.CodeIncomplete, "pack 不存在：%s", rel).
				WithScope("该文件可能尚未从云端同步下来").
				WithNext("等待网盘同步完成后重试；必要时使用 eimmortal restore --wait-for-packs")
		}
		return nil, apexerr.Wrapf(err, apexerr.CodeInternal, "无法打开 pack：%s", rel)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, apexerr.Wrapf(err, apexerr.CodeInternal, "无法 stat pack：%s", rel)
	}
	if expectSize > 0 && uint64(info.Size()) != expectSize {
		f.Close()
		return nil, r.sizeMismatch(rel, info.Size(), expectSize)
	}
	if info.Size() < int64(wire.PackHeaderSize) {
		f.Close()
		return nil, apexerr.Newf(apexerr.CodeCorrupt, "pack 文件过短：%s（%d 字节）", rel, info.Size())
	}
	raw := make([]byte, wire.PackHeaderSize)
	if _, err := io.ReadFull(f, raw); err != nil {
		f.Close()
		return nil, apexerr.Wrapf(err, apexerr.CodeCorrupt, "无法读取 pack 头：%s", rel)
	}
	header, err := wire.ParsePackHeader(raw)
	if err != nil {
		f.Close()
		return nil, apexerr.Wrapf(err, apexerr.CodeCorrupt, "pack 头非法：%s", rel)
	}
	h := &packHandle{rel: rel, f: f, size: info.Size(), header: header}
	r.open[rel] = h
	return h, nil
}

func (r *PackReader) sizeMismatch(rel string, got int64, want uint64) error {
	return apexerr.Newf(apexerr.CodeIncomplete,
		"pack 大小与 journal 记录不一致：%s（实际 %d，期望 %d）", rel, got, want).
		WithScope("pack 可能尚未同步完成，或已被云端截断").
		WithNext("等待网盘同步完成后重试；若持续不一致，执行 eimmortal verify --size")
}

// OpenWithRetry retries a missing or size-mismatched pack for up to timeout,
// which is the only place eimmortal is allowed to wait for a cloud sync (spec 06.6).
func (r *PackReader) OpenWithRetry(rel string, expectSize uint64, timeout time.Duration, onWait func(name string)) (*packHandle, error) {
	if timeout <= 0 {
		return r.Open(rel, expectSize)
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := r.Open(rel, expectSize)
		if err == nil {
			return h, nil
		}
		if apexerr.CodeOf(err) != apexerr.CodeIncomplete || time.Now().After(deadline) {
			return nil, err
		}
		if onWait != nil {
			onWait(rel)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// PackID returns the pack's identity (part of every slice AAD).
func (h *packHandle) PackID() []byte { return h.header.PackID }

// Size returns the pack size in bytes.
func (h *packHandle) Size() int64 { return h.size }

// ReadSlice reads, decrypts, decompresses and verifies one slice.
func (r *PackReader) ReadSlice(h *packHandle, ref wire.SliceRef, txnID [16]byte) ([]byte, error) {
	if ref.EnvLen < wire.EnvelopeMinLen {
		return nil, apexerr.Newf(apexerr.CodeCorrupt, "切片 env_len 非法：%d", ref.EnvLen)
	}
	end := ref.Offset + uint64(ref.EnvLen)
	if end > uint64(h.size) {
		return nil, apexerr.Newf(apexerr.CodeCorrupt,
			"切片越界：%s 偏移 %d 长度 %d 超过文件大小 %d", h.rel, ref.Offset, ref.EnvLen, h.size)
	}
	buf := make([]byte, ref.EnvLen)
	if _, err := h.f.ReadAt(buf, int64(ref.Offset)); err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeCorrupt, "读取切片失败：%s@%d", h.rel, ref.Offset)
	}
	payload, codecID, plainLen, err := wire.OpenSlice(r.key, buf, h.header.PackID, ref.Offset, ref.Index, txnID[:])
	if err != nil {
		return nil, apexerr.From(err).WithScope(
			"data/" + h.rel + " 偏移 " + itoa(ref.Offset) + " 处的切片无法通过认证").
			WithNext("执行 eimmortal verify --deep 确认损坏范围")
	}
	if codecID != ref.Codec || plainLen != int(ref.PlainLen) {
		return nil, apexerr.Newf(apexerr.CodeCorrupt,
			"切片元数据与信封不一致：codec %d/%d plain_len %d/%d", codecID, ref.Codec, plainLen, ref.PlainLen)
	}
	plain, err := codec.Decompress(codecID, payload, plainLen)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeCorrupt, "切片解压失败：%s@%d", h.rel, ref.Offset)
	}
	if len(plain) != int(ref.PlainLen) {
		return nil, apexerr.Newf(apexerr.CodeCorrupt,
			"切片明文长度不符：%d != %d", len(plain), ref.PlainLen)
	}
	sum := sha256.Sum256(plain)
	if sum != ref.PlainSHA256 {
		return nil, apexerr.Newf(apexerr.CodeCorrupt,
			"切片明文 SHA-256 不符：%s@%d", h.rel, ref.Offset).
			WithNext("执行 eimmortal verify --deep 定位损坏的 pack")
	}
	return plain, nil
}

// VerifyPack recomputes the whole-file SHA-256 recorded in the journal (D-05).
func (r *PackReader) VerifyPack(ref wire.PackRef) error {
	abs, err := r.layout.AbsPath(ref.Name)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Clean(abs))
	if err != nil {
		if os.IsNotExist(err) {
			return apexerr.Newf(apexerr.CodeIncomplete, "pack 不存在：%s", ref.Name)
		}
		return apexerr.Wrapf(err, apexerr.CodeInternal, "无法打开 pack：%s", ref.Name)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeCorrupt, "读取 pack 失败：%s", ref.Name)
	}
	if uint64(n) != ref.Size {
		return apexerr.Newf(apexerr.CodeCorrupt, "pack 大小不符：%s（%d != %d）", ref.Name, n, ref.Size)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if sum != ref.SHA256 {
		return apexerr.Newf(apexerr.CodeCorrupt, "pack SHA-256 不符：%s", ref.Name).
			WithNext("执行 eimmortal verify --deep 确认损坏范围")
	}
	return nil
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
