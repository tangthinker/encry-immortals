package store

import (
	"crypto/sha256"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// PackWriter appends slices into packs and publishes each pack atomically
// (spec 03.6 rollover, 05.1 S2/S3). It is not safe for concurrent use: one
// writer owns one pack sequence.
type PackWriter struct {
	layout       *Layout
	key          []byte
	txnID        [16]byte
	packMaxBytes uint64
	maxSlices    int

	cur    *currentPack
	packs  []wire.PackRef
	closed bool
}

type currentPack struct {
	file    *os.File
	tmpPath string
	relName string
	packID  []byte
	offset  uint64
	entries []wire.FooterEntry
	hasher  hash.Hash
}

// NewPackWriter validates the parameters that the rollover algorithm depends on
// (spec 03.6: illegal combinations must fail at startup, not mid-write).
func NewPackWriter(layout *Layout, storageKey []byte, txnID [16]byte, packMaxBytes uint64, maxSlices int) (*PackWriter, error) {
	if len(storageKey) != vaultcrypto.KeyLen {
		return nil, apexerr.Newf(apexerr.CodeUsage, "内部错误：storage key 长度 %d", len(storageKey))
	}
	if packMaxBytes < uint64(wire.PackHeaderSize+wire.EnvelopeMinLen) {
		return nil, apexerr.Newf(apexerr.CodeUsage, "pack_max_bytes=%d 太小", packMaxBytes)
	}
	if maxSlices <= 0 {
		return nil, apexerr.New(apexerr.CodeUsage, "max_slices_per_pack 必须为正数")
	}
	if err := os.MkdirAll(layout.StagingDir, 0o755); err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建暂存目录：%s", layout.StagingDir)
	}
	return &PackWriter{
		layout:       layout,
		key:          storageKey,
		txnID:        txnID,
		packMaxBytes: packMaxBytes,
		maxSlices:    maxSlices,
	}, nil
}

// Append writes one slice and returns its address record.
//
// plainLen is the pre-compression length and plainSHA the SHA-256 of the same
// uncompressed bytes (spec D-17). The caller compresses first because only it
// can compute both.
func (w *PackWriter) Append(codecID byte, plainLen int, payload []byte, plainSHA [32]byte, index uint32) (wire.SliceRef, error) {
	var zero wire.SliceRef
	if w.closed {
		return zero, errors.New("store: pack writer is closed")
	}
	envLen := uint64(wire.EnvelopeMinLen + len(payload))
	if uint64(wire.PackHeaderSize)+envLen > w.packMaxBytes {
		return zero, apexerr.Newf(apexerr.CodeUsage,
			"单切片信封 %d 字节放不进 pack_max_bytes=%d", envLen, w.packMaxBytes).
			WithNext("调大 storage.pack_max_bytes，或调小 storage.slice_plain_bytes")
	}
	if w.cur == nil || w.cur.offset+envLen > w.packMaxBytes || len(w.cur.entries) >= w.maxSlices {
		if err := w.sealCurrent(); err != nil {
			return zero, err
		}
		if err := w.startNew(); err != nil {
			return zero, err
		}
	}
	env, err := wire.SealSlice(w.key, codecID, plainLen, payload, w.cur.packID, w.cur.offset, index, w.txnID[:])
	if err != nil {
		return zero, apexerr.Wrap(err, apexerr.CodeInternal, "无法生成切片信封")
	}
	if uint64(len(env)) != envLen {
		return zero, apexerr.Newf(apexerr.CodeInternal, "信封长度自检失败：%d != %d", len(env), envLen)
	}
	if _, err := w.cur.file.Write(env); err != nil {
		return zero, apexerr.Wrapf(err, apexerr.CodeNoSpace, "写入暂存 pack 失败：%s", w.cur.tmpPath)
	}
	w.cur.hasher.Write(env)
	ref := wire.SliceRef{
		PackIdx:     uint32(len(w.packs)),
		Offset:      w.cur.offset,
		EnvLen:      uint32(len(env)),
		PlainLen:    uint32(plainLen),
		Index:       index,
		Codec:       codecID,
		PlainSHA256: plainSHA,
	}
	w.cur.entries = append(w.cur.entries, wire.FooterEntry{
		Offset: ref.Offset, EnvLen: ref.EnvLen, PlainLen: ref.PlainLen, Index: ref.Index,
	})
	w.cur.offset += uint64(len(env))
	return ref, nil
}

// SealAll seals the in-flight pack and returns every pack produced by this
// writer, in pack_idx order.
func (w *PackWriter) SealAll() ([]wire.PackRef, error) {
	if w.closed {
		return nil, errors.New("store: pack writer is closed")
	}
	if err := w.sealCurrent(); err != nil {
		return nil, err
	}
	w.closed = true
	out := make([]wire.PackRef, len(w.packs))
	copy(out, w.packs)
	return out, nil
}

// Packs returns the packs sealed so far.
func (w *PackWriter) Packs() []wire.PackRef {
	out := make([]wire.PackRef, len(w.packs))
	copy(out, w.packs)
	return out
}

// Abort discards the in-flight pack and leaves published packs untouched.
func (w *PackWriter) Abort() {
	w.closed = true
	c := w.cur
	w.cur = nil
	if c == nil {
		return
	}
	c.file.Close()
	os.Remove(c.tmpPath)
}

func (w *PackWriter) startNew() error {
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		now := time.Now()
		relName, err := w.layout.NewPackRelName(now)
		if err != nil {
			return err
		}
		tmpPath := filepath.Join(w.layout.StagingDir, filepath.Base(relName))
		f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if os.IsExist(err) {
				lastErr = err
				continue
			}
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建暂存 pack：%s", tmpPath)
		}
		header, err := wire.NewPackHeader(now.Unix())
		if err != nil {
			f.Close()
			os.Remove(tmpPath)
			return apexerr.Wrap(err, apexerr.CodeInternal, "无法生成 pack 头")
		}
		header.Flags = wire.PackFlagHasFooter
		raw, err := header.Encode()
		if err != nil {
			f.Close()
			os.Remove(tmpPath)
			return apexerr.Wrap(err, apexerr.CodeInternal, "无法编码 pack 头")
		}
		if _, err := f.Write(raw); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "写入 pack 头失败：%s", tmpPath)
		}
		h := sha256.New()
		h.Write(raw)
		w.cur = &currentPack{
			file:    f,
			tmpPath: tmpPath,
			relName: relName,
			packID:  header.PackID,
			offset:  uint64(wire.PackHeaderSize),
			hasher:  h,
		}
		return nil
	}
	return apexerr.Wrap(lastErr, apexerr.CodeInternal, "无法生成唯一的 pack 文件名")
}

func (w *PackWriter) sealCurrent() error {
	c := w.cur
	if c == nil {
		return nil
	}
	fail := func(err error) error {
		c.file.Close()
		os.Remove(c.tmpPath)
		return err
	}
	footer, err := wire.SealFooter(w.key, c.packID, c.offset, c.entries)
	if err != nil {
		return fail(apexerr.Wrap(err, apexerr.CodeInternal, "无法生成 pack footer"))
	}
	if _, err := c.file.Write(footer); err != nil {
		return fail(apexerr.Wrapf(err, apexerr.CodeNoSpace, "写入 pack footer 失败：%s", c.tmpPath))
	}
	c.hasher.Write(footer)
	size := c.offset + uint64(len(footer))
	finalPath, err := w.layout.AbsPath(c.relName)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return fail(apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建 pack 分片目录：%s", filepath.Dir(finalPath)))
	}
	if err := CommitStaged(c.file, c.tmpPath, finalPath); err != nil {
		return fail(err)
	}
	var sum [32]byte
	copy(sum[:], c.hasher.Sum(nil))
	w.packs = append(w.packs, wire.PackRef{
		Name:       c.relName,
		Size:       size,
		SHA256:     sum,
		SliceCount: uint32(len(c.entries)),
	})
	w.cur = nil
	return nil
}
