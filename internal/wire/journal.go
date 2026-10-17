package wire

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/wire/mpack"
)

// Journal body schema (spec §04.2 / D-10): positional arrays, no maps.
const (
	// JournalFormatVersion is the payload schema version (independent of ver_alg).
	JournalFormatVersion = 3
	// JournalFlagFinal marks the last journal of a split transaction.
	JournalFlagFinal uint8 = 0x01
	// MaxOpsPerJournal is the split threshold from spec §04.6.
	MaxOpsPerJournal = 200_000
	// MaxJournalPlainBytes caps a decompressed journal body (§04.6).
	MaxJournalPlainBytes = 256 << 20
	// MaxPathBytes is the per-path hard limit (§09.6: 255 B per name, generous
	// overall cap for the whole relative path).
	MaxPathBytes = 4096
	// maxTreeNodes / maxPackRefs / maxDirs are defensive decode caps.
	maxTreeNodes = 4 << 20
	maxPackRefs  = 1 << 20
	maxDirs      = 4 << 20
	maxSlicesOp  = 1 << 20
)

// Journal payload kinds.
const (
	KindCommit     uint8 = 0
	KindCheckpoint uint8 = 1
	KindNote       uint8 = 2
)

// OpType enumerates the journal operation alphabet (D-09).
type OpType uint8

const (
	OpAdd     OpType = 0
	OpModify  OpType = 1
	OpDelete  OpType = 2
	OpMkdir   OpType = 3
	OpRmdir   OpType = 4
	OpSymlink OpType = 5
	OpMeta    OpType = 6
)

// String renders the op type for logs.
func (t OpType) String() string {
	switch t {
	case OpAdd:
		return "ADD"
	case OpModify:
		return "MODIFY"
	case OpDelete:
		return "DELETE"
	case OpMkdir:
		return "MKDIR"
	case OpRmdir:
		return "RMDIR"
	case OpSymlink:
		return "SYMLINK"
	case OpMeta:
		return "META"
	}
	return fmt.Sprintf("OP(%d)", uint8(t))
}

// VaultParams is the frozen parameter snapshot stored in every journal (§03.6).
type VaultParams struct {
	SlicePlainBytes uint64
	SmallFileBytes  uint64
	PackMaxBytes    uint64
	SessionMaxMiB   uint64
}

// PackRef fingerprints one pack written by the transaction (D-05).
type PackRef struct {
	Name       string
	Size       uint64
	SHA256     [32]byte
	SliceCount uint32
}

// DirEntry records a directory's mode and mtime (D-09).
type DirEntry struct {
	Path      string
	Mode      uint32
	ModTimeNS int64
}

// SliceRef addresses one slice inside a pack (D-17).
type SliceRef struct {
	PackIdx     uint32
	Offset      uint64
	EnvLen      uint32
	PlainLen    uint32
	Index       uint32
	Codec       byte
	PlainSHA256 [32]byte
}

// Op is one delta entry.
type Op struct {
	Type          OpType
	Path          string
	Mode          uint32
	Size          uint64
	ModTimeNS     int64
	ContentSHA256 [32]byte
	Slices        []SliceRef
	Extra         string
}

// FileNode is one entry of a checkpoint tree.
type FileNode struct {
	Path          string
	Mode          uint32
	Size          uint64
	ModTimeNS     int64
	ContentSHA256 [32]byte
	Slices        []SliceRef
}

// Journal is the decoded body of one journal file.
type Journal struct {
	FormatVersion uint8
	Seq           uint64
	TxnID         [16]byte
	TSUnix        int64
	Msg           string
	PrevHash      [32]byte
	Flags         uint8

	Kind   uint8
	Params VaultParams
	Packs  []PackRef
	Dirs   []DirEntry
	Ops    []Op
	Tree   []FileNode
}

// Final reports whether this journal closes its transaction (§04.6).
func (j *Journal) Final() bool { return j.Flags&JournalFlagFinal != 0 }

// corruptf formats a corrupt-data error.
func corruptf(format string, args ...any) *apexerr.Error {
	return apexerr.Newf(apexerr.CodeCorrupt, format, args...)
}

// EncodeJournalBody serialises a journal body after full validation.
func EncodeJournalBody(j *Journal) ([]byte, error) {
	if j == nil {
		return nil, fmt.Errorf("wire: nil journal")
	}
	if err := ValidateJournal(j); err != nil {
		return nil, err
	}
	return encodeJournalBodyRaw(j), nil
}

// encodeJournalBodyRaw serialises without validating. Only tests use it, to
// produce deliberately malformed bodies and prove the decoder rejects them.
func encodeJournalBodyRaw(j *Journal) []byte {
	e := mpack.NewEncoder(4096)
	e.Array(8)
	e.Uint(uint64(j.FormatVersion)).
		Uint(j.Seq).
		Bin(j.TxnID[:]).
		Int(j.TSUnix).
		Str(j.Msg).
		Bin(j.PrevHash[:]).
		Uint(uint64(j.Flags))
	e.Array(5)
	e.Uint(uint64(j.Kind))
	e.Array(4).
		Uint(j.Params.SlicePlainBytes).
		Uint(j.Params.SmallFileBytes).
		Uint(j.Params.PackMaxBytes).
		Uint(j.Params.SessionMaxMiB)
	e.Array(len(j.Packs))
	for _, p := range j.Packs {
		e.Array(4).Str(p.Name).Uint(p.Size).Bin(p.SHA256[:]).Uint(uint64(p.SliceCount))
	}
	e.Array(len(j.Dirs))
	for _, d := range j.Dirs {
		e.Array(3).Str(d.Path).Uint(uint64(d.Mode)).Int(d.ModTimeNS)
	}
	if j.Kind == KindCheckpoint {
		e.Array(len(j.Tree))
		for _, n := range j.Tree {
			e.Array(6).Str(n.Path).Uint(uint64(n.Mode)).Uint(n.Size).Int(n.ModTimeNS).
				Bin(n.ContentSHA256[:])
			encodeSlices(e, n.Slices)
		}
	} else {
		e.Array(len(j.Ops))
		for _, op := range j.Ops {
			e.Array(8).Uint(uint64(op.Type)).Str(op.Path).Uint(uint64(op.Mode)).
				Uint(op.Size).Int(op.ModTimeNS).Bin(op.ContentSHA256[:])
			encodeSlices(e, op.Slices)
			e.Str(op.Extra)
		}
	}
	return e.Bytes()
}

func encodeSlices(e *mpack.Encoder, s []SliceRef) {
	e.Array(len(s))
	for _, sl := range s {
		e.Array(7).Uint(uint64(sl.PackIdx)).Uint(sl.Offset).Uint(uint64(sl.EnvLen)).
			Uint(uint64(sl.PlainLen)).Uint(uint64(sl.Index)).Uint(uint64(sl.Codec)).
			Bin(sl.PlainSHA256[:])
	}
}

// DecodeJournalBody parses and structurally validates a journal body.
func DecodeJournalBody(b []byte) (*Journal, error) {
	if len(b) > MaxJournalPlainBytes {
		return nil, corruptf("journal 明文超过上限：%d > %d", len(b), MaxJournalPlainBytes)
	}
	d := mpack.NewDecoder(b)
	n, err := d.Array()
	if err != nil {
		return nil, corruptf("journal 顶层不是数组").WithErr(err)
	}
	if n != 8 {
		return nil, corruptf("journal 顶层元素数 %d，期望 8", n)
	}
	j := &Journal{}
	fv, err := d.Uint()
	if err != nil {
		return nil, corruptf("journal 版本字段损坏").WithErr(err)
	}
	if fv != JournalFormatVersion {
		return nil, corruptf("journal body 版本 %d 不受支持（当前 %d）", fv, JournalFormatVersion)
	}
	j.FormatVersion = uint8(fv)
	if j.Seq, err = d.Uint(); err != nil {
		return nil, corruptf("journal seq 字段损坏").WithErr(err)
	}
	txn, err := d.Bin()
	if err != nil || len(txn) != 16 {
		return nil, corruptf("journal txn_id 字段损坏").WithErr(err)
	}
	copy(j.TxnID[:], txn)
	if j.TSUnix, err = d.Int(); err != nil {
		return nil, corruptf("journal 时间戳字段损坏").WithErr(err)
	}
	if j.Msg, err = d.Str(); err != nil {
		return nil, corruptf("journal message 字段损坏").WithErr(err)
	}
	prev, err := d.Bin()
	if err != nil || len(prev) != 32 {
		return nil, corruptf("journal prev_hash 字段损坏").WithErr(err)
	}
	copy(j.PrevHash[:], prev)
	flags, err := d.Uint()
	if err != nil {
		return nil, corruptf("journal flags 字段损坏").WithErr(err)
	}
	if flags&^uint64(JournalFlagFinal) != 0 {
		return nil, corruptf("journal flags 含未知位：0x%x", flags)
	}
	j.Flags = uint8(flags)

	pn, err := d.Array()
	if err != nil {
		return nil, corruptf("journal payload 不是数组").WithErr(err)
	}
	if pn != 5 {
		return nil, corruptf("journal payload 元素数 %d，期望 5", pn)
	}
	kind, err := d.Uint()
	if err != nil {
		return nil, corruptf("journal kind 字段损坏").WithErr(err)
	}
	if kind > uint64(KindNote) {
		return nil, corruptf("journal kind %d 未知", kind)
	}
	j.Kind = uint8(kind)

	vn, err := d.Array()
	if err != nil || vn != 4 {
		return nil, corruptf("journal vault_params 结构非法").WithErr(err)
	}
	if j.Params.SlicePlainBytes, err = d.Uint(); err != nil {
		return nil, corruptf("vault_params 损坏").WithErr(err)
	}
	if j.Params.SmallFileBytes, err = d.Uint(); err != nil {
		return nil, corruptf("vault_params 损坏").WithErr(err)
	}
	if j.Params.PackMaxBytes, err = d.Uint(); err != nil {
		return nil, corruptf("vault_params 损坏").WithErr(err)
	}
	if j.Params.SessionMaxMiB, err = d.Uint(); err != nil {
		return nil, corruptf("vault_params 损坏").WithErr(err)
	}

	packsN, err := d.Array()
	if err != nil {
		return nil, corruptf("journal packs 不是数组").WithErr(err)
	}
	if packsN > maxPackRefs {
		return nil, corruptf("journal packs 数量 %d 超限", packsN)
	}
	j.Packs = alloc[PackRef](packsN)
	for i := 0; i < packsN; i++ {
		en, err := d.Array()
		if err != nil || en != 4 {
			return nil, corruptf("pack 引用结构非法").WithErr(err)
		}
		p := PackRef{}
		if p.Name, err = d.Str(); err != nil {
			return nil, corruptf("pack 名称损坏").WithErr(err)
		}
		if err := validatePackName(p.Name); err != nil {
			return nil, err
		}
		if p.Size, err = d.Uint(); err != nil {
			return nil, corruptf("pack 大小损坏").WithErr(err)
		}
		sha, err := d.Bin()
		if err != nil || len(sha) != 32 {
			return nil, corruptf("pack sha256 损坏").WithErr(err)
		}
		copy(p.SHA256[:], sha)
		sc, err := d.Uint()
		if err != nil {
			return nil, corruptf("pack 切片数损坏").WithErr(err)
		}
		p.SliceCount = uint32(sc)
		j.Packs[i] = p
	}

	dirsN, err := d.Array()
	if err != nil {
		return nil, corruptf("journal dirs 不是数组").WithErr(err)
	}
	if dirsN > maxDirs {
		return nil, corruptf("journal dirs 数量 %d 超限", dirsN)
	}
	j.Dirs = alloc[DirEntry](dirsN)
	for i := 0; i < dirsN; i++ {
		en, err := d.Array()
		if err != nil || en != 3 {
			return nil, corruptf("目录条目结构非法").WithErr(err)
		}
		de := DirEntry{}
		if de.Path, err = d.Str(); err != nil {
			return nil, corruptf("目录路径损坏").WithErr(err)
		}
		if err := validateRelPath(de.Path); err != nil {
			return nil, err
		}
		mode, err := d.Uint()
		if err != nil {
			return nil, corruptf("目录 mode 损坏").WithErr(err)
		}
		if mode&^uint64(0o7777) != 0 {
			return nil, corruptf("目录 mode 含非法位：0o%o", mode)
		}
		de.Mode = uint32(mode)
		if de.ModTimeNS, err = d.Int(); err != nil {
			return nil, corruptf("目录 mtime 损坏").WithErr(err)
		}
		j.Dirs[i] = de
	}

	if j.Kind == KindCheckpoint {
		treeN, err := d.Array()
		if err != nil {
			return nil, corruptf("checkpoint tree 不是数组").WithErr(err)
		}
		if treeN > maxTreeNodes {
			return nil, corruptf("checkpoint tree 节点数 %d 超限", treeN)
		}
		j.Tree = alloc[FileNode](treeN)
		for i := 0; i < treeN; i++ {
			en, err := d.Array()
			if err != nil || en != 6 {
				return nil, corruptf("checkpoint 节点结构非法").WithErr(err)
			}
			n := FileNode{}
			if n.Path, err = d.Str(); err != nil {
				return nil, corruptf("checkpoint 路径损坏").WithErr(err)
			}
			if err := validateRelPath(n.Path); err != nil {
				return nil, err
			}
			mode, err := d.Uint()
			if err != nil || mode&^uint64(0o7777) != 0 {
				return nil, corruptf("checkpoint mode 非法")
			}
			n.Mode = uint32(mode)
			if n.Size, err = d.Uint(); err != nil {
				return nil, corruptf("checkpoint size 损坏").WithErr(err)
			}
			if n.ModTimeNS, err = d.Int(); err != nil {
				return nil, corruptf("checkpoint mtime 损坏").WithErr(err)
			}
			sha, err := d.Bin()
			if err != nil || len(sha) != 32 {
				return nil, corruptf("checkpoint content_sha256 损坏").WithErr(err)
			}
			copy(n.ContentSHA256[:], sha)
			slices, err := decodeSlices(d, j.Packs)
			if err != nil {
				return nil, err
			}
			n.Slices = slices
			if err := validateSlicesForSize(n.Slices, n.Size); err != nil {
				return nil, err
			}
			j.Tree[i] = n
		}
	} else {
		opsN, err := d.Array()
		if err != nil {
			return nil, corruptf("journal ops 不是数组").WithErr(err)
		}
		if opsN > MaxOpsPerJournal {
			return nil, corruptf("journal ops 数量 %d 超过上限 %d", opsN, MaxOpsPerJournal)
		}
		j.Ops = alloc[Op](opsN)
		for i := 0; i < opsN; i++ {
			en, err := d.Array()
			if err != nil || en != 8 {
				return nil, corruptf("op 结构非法").WithErr(err)
			}
			op := Op{}
			typ, err := d.Uint()
			if err != nil || typ > uint64(OpMeta) {
				return nil, corruptf("op_type 非法")
			}
			op.Type = OpType(typ)
			if op.Path, err = d.Str(); err != nil {
				return nil, corruptf("op 路径损坏").WithErr(err)
			}
			if err := validateRelPath(op.Path); err != nil {
				return nil, err
			}
			mode, err := d.Uint()
			if err != nil || mode&^uint64(0o7777) != 0 {
				return nil, corruptf("op mode 非法")
			}
			op.Mode = uint32(mode)
			if op.Size, err = d.Uint(); err != nil {
				return nil, corruptf("op size 损坏").WithErr(err)
			}
			if op.ModTimeNS, err = d.Int(); err != nil {
				return nil, corruptf("op mtime 损坏").WithErr(err)
			}
			sha, err := d.Bin()
			if err != nil || len(sha) != 32 {
				return nil, corruptf("op content_sha256 损坏").WithErr(err)
			}
			copy(op.ContentSHA256[:], sha)
			slices, err := decodeSlices(d, j.Packs)
			if err != nil {
				return nil, err
			}
			op.Slices = slices
			if op.Extra, err = d.Str(); err != nil {
				return nil, corruptf("op extra 损坏").WithErr(err)
			}
			if err := validateOp(&op, len(j.Packs)); err != nil {
				return nil, err
			}
			j.Ops[i] = op
		}
	}
	if err := d.ErrTrailing(); err != nil {
		return nil, corruptf("journal 尾部有多余字节").WithErr(err)
	}
	return j, nil
}

// alloc returns nil for an empty count so that decode/encode round trips keep
// nil and empty slices distinguishable from each other.
func alloc[T any](n int) []T {
	if n == 0 {
		return nil
	}
	return make([]T, n)
}

func decodeSlices(d *mpack.Decoder, packs []PackRef) ([]SliceRef, error) {
	n, err := d.Array()
	if err != nil {
		return nil, corruptf("slices 不是数组").WithErr(err)
	}
	if n > maxSlicesOp {
		return nil, corruptf("slices 数量 %d 超限", n)
	}
	out := alloc[SliceRef](n)
	for i := 0; i < n; i++ {
		en, err := d.Array()
		if err != nil || en != 7 {
			return nil, corruptf("slice 结构非法").WithErr(err)
		}
		s := SliceRef{}
		pi, err := d.Uint()
		if err != nil {
			return nil, corruptf("slice pack_idx 损坏").WithErr(err)
		}
		if pi >= uint64(len(packs)) {
			return nil, corruptf("slice pack_idx %d 超出 packs 数量 %d", pi, len(packs))
		}
		s.PackIdx = uint32(pi)
		if s.Offset, err = d.Uint(); err != nil {
			return nil, corruptf("slice offset 损坏").WithErr(err)
		}
		envLen, err := d.Uint()
		if err != nil {
			return nil, corruptf("slice env_len 损坏").WithErr(err)
		}
		plainLen, err := d.Uint()
		if err != nil {
			return nil, corruptf("slice plain_len 损坏").WithErr(err)
		}
		idx, err := d.Uint()
		if err != nil {
			return nil, corruptf("slice index 损坏").WithErr(err)
		}
		if idx != uint64(i) {
			return nil, corruptf("slice index %d 应当等于位置 %d", idx, i)
		}
		s.Index = uint32(idx)
		codecID, err := d.Uint()
		if err != nil {
			return nil, corruptf("slice codec 损坏").WithErr(err)
		}
		if codecID != uint64(codec.None) && codecID != uint64(codec.Zstd) {
			return nil, corruptf("slice codec 非法：%d", codecID)
		}
		if envLen < EnvelopeMinLen || envLen > EnvelopeMinLen+maxCompressedLen {
			return nil, corruptf("slice env_len %d 超出范围", envLen)
		}
		if plainLen == 0 || plainLen > MaxSlicePlainHard {
			return nil, corruptf("slice plain_len %d 超出范围", plainLen)
		}
		s.EnvLen = uint32(envLen)
		s.PlainLen = uint32(plainLen)
		s.Codec = byte(codecID)
		sha, err := d.Bin()
		if err != nil || len(sha) != 32 {
			return nil, corruptf("slice plain_sha256 损坏").WithErr(err)
		}
		copy(s.PlainSHA256[:], sha)
		out[i] = s
	}
	return out, nil
}

func validateSlicesForSize(slices []SliceRef, size uint64) error {
	if size == 0 {
		if len(slices) != 0 {
			return corruptf("0 字节文件不应包含切片（有 %d 个）", len(slices))
		}
		return nil
	}
	if len(slices) == 0 {
		return corruptf("非空文件（%d 字节）缺少切片", size)
	}
	return nil
}

func validateOp(op *Op, packCount int) error {
	switch op.Type {
	case OpAdd, OpModify:
		if err := validateSlicesForSize(op.Slices, op.Size); err != nil {
			return err
		}
		if op.Extra != "" {
			return corruptf("%s 操作的 extra 必须为空", op.Type)
		}
	case OpSymlink:
		if len(op.Slices) != 0 {
			return corruptf("SYMLINK 不应携带切片")
		}
		if op.Extra == "" {
			return corruptf("SYMLINK 缺少链接目标")
		}
		if strings.ContainsRune(op.Extra, 0) {
			return corruptf("SYMLINK 目标含 NUL")
		}
	default:
		if len(op.Slices) != 0 {
			return corruptf("%s 操作不应携带切片", op.Type)
		}
		if op.Extra != "" {
			return corruptf("%s 操作的 extra 必须为空", op.Type)
		}
	}
	return nil
}

// ValidateJournal checks every structural rule before encoding.
func ValidateJournal(j *Journal) error {
	if j.FormatVersion != JournalFormatVersion {
		return fmt.Errorf("wire: journal format version %d is not %d", j.FormatVersion, JournalFormatVersion)
	}
	if j.Flags&^JournalFlagFinal != 0 {
		return fmt.Errorf("wire: unknown journal flags 0x%x", j.Flags)
	}
	if j.Kind > KindNote {
		return fmt.Errorf("wire: unknown journal kind %d", j.Kind)
	}
	if len(j.Packs) > maxPackRefs || len(j.Dirs) > maxDirs || len(j.Ops) > MaxOpsPerJournal {
		return fmt.Errorf("wire: journal exceeds size limits")
	}
	for _, p := range j.Packs {
		if err := validatePackName(p.Name); err != nil {
			return err
		}
	}
	for _, d := range j.Dirs {
		if err := validateRelPath(d.Path); err != nil {
			return err
		}
		if d.Mode&^0o7777 != 0 {
			return fmt.Errorf("wire: dir mode 0o%o has type bits", d.Mode)
		}
	}
	for i := range j.Ops {
		op := &j.Ops[i]
		if err := validateRelPath(op.Path); err != nil {
			return err
		}
		if op.Mode&^0o7777 != 0 {
			return fmt.Errorf("wire: op mode 0o%o has type bits", op.Mode)
		}
		for k := range op.Slices {
			s := &op.Slices[k]
			if s.Index != uint32(k) {
				return fmt.Errorf("wire: slice index %d must equal position %d", s.Index, k)
			}
			if s.PackIdx >= uint32(len(j.Packs)) {
				return fmt.Errorf("wire: slice pack_idx %d out of range", s.PackIdx)
			}
			if s.EnvLen < EnvelopeMinLen || s.EnvLen > EnvelopeMinLen+maxCompressedLen {
				return fmt.Errorf("wire: slice env_len %d out of range", s.EnvLen)
			}
			if s.PlainLen == 0 || s.PlainLen > MaxSlicePlainHard {
				return fmt.Errorf("wire: slice plain_len %d out of range", s.PlainLen)
			}
			if s.Codec != codec.None && s.Codec != codec.Zstd {
				return fmt.Errorf("wire: slice codec %d invalid", s.Codec)
			}
		}
		if err := validateOp(op, len(j.Packs)); err != nil {
			return err
		}
	}
	for i := range j.Tree {
		n := &j.Tree[i]
		if err := validateRelPath(n.Path); err != nil {
			return err
		}
		if n.Mode&^0o7777 != 0 {
			return fmt.Errorf("wire: tree mode 0o%o has type bits", n.Mode)
		}
		for k := range n.Slices {
			s := &n.Slices[k]
			if s.Index != uint32(k) {
				return fmt.Errorf("wire: slice index %d must equal position %d", s.Index, k)
			}
			if s.PackIdx >= uint32(len(j.Packs)) {
				return fmt.Errorf("wire: slice pack_idx %d out of range", s.PackIdx)
			}
		}
		if err := validateSlicesForSize(n.Slices, n.Size); err != nil {
			return err
		}
	}
	return nil
}

// validateRelPath enforces the structural path rules of the spec's global
// conventions. NFC normalisation and case-fold collision checks live in pathx
// because they are platform policy, not wire format.
func validateRelPath(p string) error {
	if p == "" {
		return corruptf("路径为空")
	}
	if len(p) > MaxPathBytes {
		return corruptf("路径长度 %d 超过上限 %d", len(p), MaxPathBytes)
	}
	if !utf8.ValidString(p) {
		return corruptf("路径不是合法 UTF-8")
	}
	if strings.ContainsRune(p, 0) {
		return corruptf("路径含 NUL")
	}
	if strings.HasPrefix(p, "/") {
		return corruptf("路径为绝对路径：%q", p)
	}
	if strings.Contains(p, "\\") {
		return corruptf("路径含反斜杠：%q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "":
			return corruptf("路径含空段：%q", p)
		case ".":
			return corruptf("路径含 '.' 段：%q", p)
		case "..":
			return corruptf("路径含 '..' 段：%q", p)
		}
		if len(seg) > 255 {
			return corruptf("路径段超过 255 字节：%q", seg)
		}
	}
	return nil
}

// validatePackName enforces the "data/.../pack_*.dat" relative path from §06.3.
func validatePackName(name string) error {
	if name == "" {
		return corruptf("pack 名称为空")
	}
	if len(name) > MaxPathBytes {
		return corruptf("pack 名称过长")
	}
	if strings.ContainsRune(name, 0) {
		return corruptf("pack 名称含 NUL")
	}
	if !strings.HasPrefix(name, "data/") || !strings.HasSuffix(name, ".dat") {
		return corruptf("pack 名称必须是 data/....dat：%q", name)
	}
	if strings.Contains(name, "..") {
		return corruptf("pack 名称含 '..'：%q", name)
	}
	return nil
}

// Journal file container constants (spec §04.1).
const (
	// JournalFileHeaderSize = ver_alg(1) + codec(1) + reserved(2) + nonce(24).
	JournalFileHeaderSize = 28
	// JournalFileMinSize is header + tag.
	JournalFileMinSize = JournalFileHeaderSize + vaultcrypto.TagLen
)

// SealJournalFile compresses, encrypts and frames a journal body.
func SealJournalFile(journalKey []byte, seq uint64, vaultID, body []byte) ([]byte, error) {
	nonce, err := vaultcrypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	return SealJournalFileWithNonce(journalKey, seq, vaultID, body, nonce)
}

// SealJournalFileWithNonce is SealJournalFile with a caller-supplied nonce; only
// golden vectors and tests may use it (I18).
func SealJournalFileWithNonce(journalKey []byte, seq uint64, vaultID, body, nonce []byte) ([]byte, error) {
	if len(body) > MaxJournalPlainBytes {
		return nil, fmt.Errorf("wire: journal body %d bytes exceeds the %d cap", len(body), MaxJournalPlainBytes)
	}
	if len(nonce) != vaultcrypto.NonceLen {
		return nil, fmt.Errorf("wire: nonce must be %d bytes", vaultcrypto.NonceLen)
	}
	codecID, payload, err := codec.Compress(body)
	if err != nil {
		return nil, err
	}
	aad, err := vaultcrypto.JournalAAD(vaultcrypto.VerAlg, codecID, seq, vaultID)
	if err != nil {
		return nil, err
	}
	ct, err := vaultcrypto.Seal(journalKey, nonce, payload, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, JournalFileHeaderSize+len(ct))
	out = append(out, vaultcrypto.VerAlg, codecID, 0, 0)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenJournalFile authenticates, decrypts and decompresses a journal file.
//
// seq must be the sequence parsed from the file name: it is part of the AAD, so
// renaming a journal breaks decryption (I6).
func OpenJournalFile(journalKey []byte, seq uint64, vaultID, raw []byte) ([]byte, error) {
	if len(raw) < JournalFileMinSize {
		return nil, corruptf("journal 文件过短：%d 字节", len(raw))
	}
	if raw[0] != vaultcrypto.VerAlg {
		return nil, corruptf("journal 版本/算法不受支持：ver_alg=0x%02x", raw[0])
	}
	codecID := raw[1]
	if codecID != codec.None && codecID != codec.Zstd {
		return nil, corruptf("journal codec 非法：%d", codecID)
	}
	if binary.BigEndian.Uint16(raw[2:4]) != 0 {
		return nil, corruptf("journal reserved 字段非零")
	}
	nonce := raw[4:JournalFileHeaderSize]
	ct := raw[JournalFileHeaderSize:]
	aad, err := vaultcrypto.JournalAAD(vaultcrypto.VerAlg, codecID, seq, vaultID)
	if err != nil {
		return nil, err
	}
	payload, err := vaultcrypto.Open(journalKey, nonce, ct, aad)
	if err != nil {
		return nil, corruptf("journal 解密失败（seq=%d）", seq).WithErr(err)
	}
	body, err := codec.Decompress(codecID, payload, MaxJournalPlainBytes)
	if err != nil {
		return nil, corruptf("journal 解压失败（seq=%d）", seq).WithErr(err)
	}
	if len(body) > MaxJournalPlainBytes {
		return nil, corruptf("journal 明文超过上限（seq=%d）", seq)
	}
	return body, nil
}

var _ = apexerr.CodeCorrupt
