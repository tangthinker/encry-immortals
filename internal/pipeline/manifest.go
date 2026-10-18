package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// Per-pack manifests are an additive index: the encrypted journal chain remains
// the authoritative commit record, while each pack gets a small encrypted file
// describing the slices it holds and the files they belong to.
const (
	manifestVersion       = 1
	manifestHeaderSize    = 4 + vaultcrypto.NonceLen
	manifestMaxPlainBytes = 64 << 20
)

// Manifest is the plaintext of one meta/manifests/<pack>.manifest file.
type Manifest struct {
	Version    int          `json:"version"`
	Pack       string       `json:"pack"`
	PackSize   uint64       `json:"pack_size"`
	PackSHA256 []byte       `json:"pack_sha256"`
	TxnID      []byte       `json:"txn_id"`
	Seq        uint64       `json:"seq"`
	Ops        []ManifestOp `json:"ops"`
}

// ManifestOp describes one file whose slices touch this pack. Slices contains
// the full file slice list; Packs maps Slice.PackIdx to pack names, so a reader
// can tell which slices are local and which need another pack.
type ManifestOp struct {
	Type          uint8           `json:"type"`
	Path          string          `json:"path"`
	Mode          uint32          `json:"mode"`
	Size          uint64          `json:"size"`
	ModTimeNS     int64           `json:"mtime_ns"`
	ContentSHA256 []byte          `json:"content_sha256"`
	Packs         []string        `json:"packs"`
	Slices        []ManifestSlice `json:"slices"`
}

type ManifestSlice struct {
	PackIdx     uint32 `json:"pack_idx"`
	Offset      uint64 `json:"offset"`
	EnvLen      uint32 `json:"env_len"`
	PlainLen    uint32 `json:"plain_len"`
	Index       uint32 `json:"index"`
	Codec       uint8  `json:"codec"`
	PlainSHA256 []byte `json:"plain_sha256"`
}

// buildManifest builds the manifest for one pack index. The boolean reports
// whether any content op touches the pack.
func buildManifest(packs []wire.PackRef, packIdx int, ops []wire.Op, txn [16]byte, seq uint64) (Manifest, bool, error) {
	if packIdx < 0 || packIdx >= len(packs) {
		return Manifest{}, false, apexerr.Newf(apexerr.CodeInternal, "manifest: pack index %d out of range", packIdx)
	}
	pack := packs[packIdx]
	doc := Manifest{
		Version:    manifestVersion,
		Pack:       pack.Name,
		PackSize:   pack.Size,
		PackSHA256: append([]byte(nil), pack.SHA256[:]...),
		TxnID:      append([]byte(nil), txn[:]...),
		Seq:        seq,
	}
	for _, op := range ops {
		if op.Type != wire.OpAdd && op.Type != wire.OpModify {
			continue
		}
		touches := false
		var packIdxes []uint32
		seen := make(map[uint32]bool)
		for _, sl := range op.Slices {
			if int(sl.PackIdx) >= len(packs) {
				return Manifest{}, false, apexerr.Newf(apexerr.CodeInternal,
					"manifest: slice %d of %s references pack %d", sl.Index, op.Path, sl.PackIdx)
			}
			if !seen[sl.PackIdx] {
				seen[sl.PackIdx] = true
				packIdxes = append(packIdxes, sl.PackIdx)
			}
			if int(sl.PackIdx) == packIdx {
				touches = true
			}
		}
		if !touches {
			continue
		}
		mo := ManifestOp{
			Type:          uint8(op.Type),
			Path:          op.Path,
			Mode:          op.Mode,
			Size:          op.Size,
			ModTimeNS:     op.ModTimeNS,
			ContentSHA256: append([]byte(nil), op.ContentSHA256[:]...),
		}
		mo.Packs = make([]string, 0, len(packIdxes))
		for _, idx := range packIdxes {
			mo.Packs = append(mo.Packs, packs[idx].Name)
		}
		mo.Slices = make([]ManifestSlice, 0, len(op.Slices))
		for _, sl := range op.Slices {
			mo.Slices = append(mo.Slices, ManifestSlice{
				PackIdx:     sl.PackIdx,
				Offset:      sl.Offset,
				EnvLen:      sl.EnvLen,
				PlainLen:    sl.PlainLen,
				Index:       sl.Index,
				Codec:       sl.Codec,
				PlainSHA256: append([]byte(nil), sl.PlainSHA256[:]...),
			})
		}
		doc.Ops = append(doc.Ops, mo)
	}
	return doc, len(doc.Ops) > 0, nil
}

// manifestAAD binds a manifest to the vault and the pack name it describes.
func manifestAAD(vaultID []byte, packName string, codecID byte) []byte {
	sum := sha256.Sum256([]byte(packName))
	aad := make([]byte, 0, 2+len(vaultID)+16)
	aad = append(aad, vaultcrypto.VerAlg, codecID)
	aad = append(aad, vaultID...)
	aad = append(aad, sum[:16]...)
	return aad
}

func sealManifest(journalKey, vaultID []byte, packName string, plain []byte) ([]byte, error) {
	if len(plain) > manifestMaxPlainBytes {
		return nil, apexerr.Newf(apexerr.CodeInternal, "manifest 明文 %d 字节超过上限", len(plain))
	}
	codecID, payload, err := codec.CompressWith(plain, codec.DefaultOptions())
	if err != nil {
		return nil, apexerr.From(err)
	}
	nonce, err := vaultcrypto.RandomNonce()
	if err != nil {
		return nil, apexerr.From(err)
	}
	ct, err := vaultcrypto.Seal(journalKey, nonce, payload, manifestAAD(vaultID, packName, codecID))
	if err != nil {
		return nil, apexerr.From(err)
	}
	out := make([]byte, 0, manifestHeaderSize+len(ct))
	out = append(out, vaultcrypto.VerAlg, codecID, 0, 0)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func openManifest(journalKey, vaultID []byte, packName string, raw []byte) (*Manifest, error) {
	if len(raw) < manifestHeaderSize+vaultcrypto.TagLen {
		return nil, apexerr.New(apexerr.CodeCorrupt, "manifest 文件过短")
	}
	if raw[0] != vaultcrypto.VerAlg {
		return nil, apexerr.Newf(apexerr.CodeCorrupt, "manifest 版本不受支持：0x%02x", raw[0])
	}
	codecID := raw[1]
	if codecID != codec.None && codecID != codec.Zstd {
		return nil, apexerr.Newf(apexerr.CodeCorrupt, "manifest codec 非法：%d", codecID)
	}
	if raw[2] != 0 || raw[3] != 0 {
		return nil, apexerr.New(apexerr.CodeCorrupt, "manifest reserved 字段非零")
	}
	nonce := raw[4:manifestHeaderSize]
	ct := raw[manifestHeaderSize:]
	payload, err := vaultcrypto.Open(journalKey, nonce, ct, manifestAAD(vaultID, packName, codecID))
	if err != nil {
		return nil, apexerr.New(apexerr.CodeCorrupt, "manifest 解密失败").WithErr(err)
	}
	plain, err := codec.Decompress(codecID, payload, manifestMaxPlainBytes)
	if err != nil {
		return nil, apexerr.New(apexerr.CodeCorrupt, "manifest 解压失败").WithErr(err)
	}
	if len(plain) > manifestMaxPlainBytes {
		return nil, apexerr.New(apexerr.CodeCorrupt, "manifest 明文超过上限")
	}
	var doc Manifest
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, apexerr.New(apexerr.CodeCorrupt, "manifest 明文结构非法").WithErr(err)
	}
	if doc.Version != manifestVersion {
		return nil, apexerr.Newf(apexerr.CodeCorrupt, "manifest 版本 %d 不受支持", doc.Version)
	}
	if doc.Pack != packName {
		return nil, apexerr.Newf(apexerr.CodeCorrupt, "manifest 属于 pack %s，不是 %s", doc.Pack, packName)
	}
	return &doc, nil
}

// writeManifests writes one encrypted manifest per pack that carries content.
// It must run after the packs are durable and before the journal commit; on
// failure the caller aborts, leaving only orphan packs/manifests for gc.
func writeManifests(layout *store.Layout, keys *vault.Keys, packs []wire.PackRef,
	ops []wire.Op, txn [16]byte, seq uint64) (int, error) {
	if len(packs) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(layout.ManifestDir, 0o700); err != nil {
		return 0, apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建 manifest 目录：%s", layout.ManifestDir)
	}
	written := 0
	for i, pack := range packs {
		doc, ok, err := buildManifest(packs, i, ops, txn, seq)
		if err != nil {
			return written, err
		}
		if !ok {
			continue
		}
		plain, err := json.Marshal(doc)
		if err != nil {
			return written, apexerr.New(apexerr.CodeInternal, "无法编码 manifest").WithErr(err)
		}
		raw, err := sealManifest(keys.Sub.Journal.Bytes(), keys.VaultID[:], pack.Name, plain)
		if err != nil {
			return written, err
		}
		rel := layout.ManifestRelPath(pack.Name)
		abs, err := layout.AbsPath(rel)
		if err != nil {
			return written, err
		}
		if err := store.WriteFileDurableAs(layout.StagingDir, filepath.Base(rel)+".tmp", abs, raw, 0o600); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// ReadManifest loads and authenticates the manifest for a pack name.
func ReadManifest(layout *store.Layout, keys *vault.Keys, packName string) (*Manifest, error) {
	rel := layout.ManifestRelPath(packName)
	abs, err := layout.AbsPath(rel)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apexerr.Newf(apexerr.CodeIncomplete, "该 pack 没有 manifest：%s", rel).
				WithNext("旧版本备份没有 manifest；重新 backup 或 compact 后会生成")
		}
		return nil, apexerr.Wrapf(err, apexerr.CodeCorrupt, "无法读取 manifest：%s", rel)
	}
	return openManifest(keys.Sub.Journal.Bytes(), keys.VaultID[:], packName, raw)
}
