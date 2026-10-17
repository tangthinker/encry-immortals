package pipeline

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	"github.com/tangthinker/encry-immortals/internal/config"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/index"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/pathx"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// CompactOptions drives "eimmortal compact" (spec 11.4): rebuild a fresh vault that
// contains only the content referenced by one snapshot.
type CompactOptions struct {
	Layout         *store.Layout // old TargetDir
	Keys           *vault.Keys   // old vault keys
	Config         *config.Config
	OutDir         string // new TargetDir (must be empty or absent)
	NewVaultDir    string // new control plane, required with NewIdentity
	NewIdentity    bool
	NewPassword    []byte
	AtSeq          uint64
	DryRun         bool
	AcceptDataLoss bool
	Probe          vault.Probe // test hook for KDF calibration
	ToolVersion    string
	Now            func() time.Time
	Progress       func(format string, args ...any)
}

// CompactResult reports what one compact produced.
type CompactResult struct {
	Seq        uint64
	Files      int
	Dirs       int
	Links      int
	Packs      []wire.PackRef
	Bytes      uint64 // logical bytes of the kept files
	PackBytes  uint64
	Dropped    []string
	NewVaultID string
	ArmorKey   string
	Duration   time.Duration
	DryRun     bool
}

// Compact never deletes anything: the old vault stays exactly as it is.
func Compact(opts CompactOptions) (*CompactResult, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logf := func(format string, args ...any) {
		if opts.Progress != nil {
			opts.Progress(format, args...)
		}
	}
	start := now()
	res := &CompactResult{DryRun: opts.DryRun}

	outDir, err := filepath.Abs(opts.OutDir)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "新 TargetDir 路径非法：%s", opts.OutDir)
	}
	if overlap, oerr := pathx.Overlap(outDir, opts.Layout.TargetDir); oerr != nil || overlap {
		return nil, apexerr.New(apexerr.CodeUsage, "新 TargetDir 不能与旧 TargetDir 重叠").
			WithNext("换一个全新的目录作为 --out")
	}
	if !opts.DryRun {
		if err := ensureEmptyDir(outDir); err != nil {
			return nil, err
		}
	}

	logf("正在校验旧库 journal 链…")
	chain, err := journal.Load(opts.Layout, opts.Keys.Sub.Journal.Bytes(), opts.Keys.VaultID[:],
		journal.LoadOptions{TargetSeq: opts.AtSeq})
	if err != nil {
		return nil, err
	}
	if chain.LastSeq == 0 {
		return nil, apexerr.New(apexerr.CodeUsage, "旧库没有任何提交，无法 compact")
	}
	files := chain.Tree.Files()
	dirs := chain.Tree.Dirs()
	links := chain.Tree.Links()
	res.Files, res.Dirs, res.Links = len(files), len(dirs), len(links)
	for _, n := range files {
		res.Bytes += n.Size
	}

	// Space pre-check (spec 11.4).
	if free, derr := store.DiskFree(outDir); derr == nil && free > 0 && uint64(free) < res.Bytes {
		return nil, apexerr.Newf(apexerr.CodeNoSpace,
			"新 TargetDir 剩余空间不足：可用 %d 字节，预计需要 %d 字节", free, res.Bytes).
			WithNext("清理磁盘或换一个容量足够的目录")
	}

	if opts.DryRun {
		res.Duration = now().Sub(start)
		return res, nil
	}

	// Resolve the key set for the new vault.
	outKeys := opts.Keys
	var newMeta *vault.Meta
	if opts.NewIdentity {
		if opts.NewVaultDir == "" {
			return nil, apexerr.New(apexerr.CodeUsage, "--new-identity 需要同时指定 --new-vault <新控制平面目录>").
				WithScope("新的 salt / vault_id 必须写在 TargetDir 之外（盲盒原则）")
		}
		if len(opts.NewPassword) == 0 {
			return nil, apexerr.New(apexerr.CodeUsage, "--new-identity 需要新的主密码")
		}
		logf("正在生成新 vault 身份（KDF 校准需要数秒）…")
		initRes, ierr := vault.Init(opts.NewVaultDir, vault.InitOptions{
			Password:    opts.NewPassword,
			Now:         now(),
			Probe:       opts.Probe,
			Force:       true,
			ToolVersion: opts.ToolVersion,
		})
		if ierr != nil {
			return nil, ierr
		}
		newMeta = initRes.Meta
		keys, kerr := newMeta.Unlock(opts.NewPassword)
		if kerr != nil {
			return nil, kerr
		}
		defer keys.Destroy()
		outKeys = keys
		res.NewVaultID = newMeta.VaultID
		if armored, aerr := newMeta.Armor(); aerr == nil {
			res.ArmorKey = armored
		}
	}

	newLayout, err := store.NewLayout(outDir, "")
	if err != nil {
		return nil, err
	}
	if err := newLayout.Ensure(); err != nil {
		return nil, err
	}

	oldReader, err := store.NewPackReader(opts.Layout, opts.Keys.Sub.Storage.Bytes())
	if err != nil {
		return nil, err
	}
	defer oldReader.Close()

	txnRaw, err := vaultcrypto.RandomBytes(16)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法生成 txn_id")
	}
	var txn [16]byte
	copy(txn[:], txnRaw)
	pw, err := store.NewPackWriter(newLayout, outKeys.Sub.Storage.Bytes(), txn,
		opts.Config.Storage.PackMaxBytes, 100_000)
	if err != nil {
		return nil, err
	}
	defer pw.Abort()

	logf("正在重新打包 %d 个文件…", len(files))
	var ops []wire.Op
	var dirEntries []wire.DirEntry
	for _, n := range dirs {
		dirEntries = append(dirEntries, wire.DirEntry{Path: n.Path, Mode: n.Mode, ModTimeNS: n.ModTimeNS})
	}
	for _, n := range dirs {
		ops = append(ops, wire.Op{Type: wire.OpMkdir, Path: n.Path, Mode: n.Mode, ModTimeNS: n.ModTimeNS})
	}
	dropped := map[string]bool{}
	for _, n := range files {
		newSlices, derr := repackFile(oldReader, pw, chain.Tree.Packs, n, opts.Config.CodecOptions())
		if derr != nil {
			if apexerr.CodeOf(derr) == apexerr.CodeIncomplete && opts.AcceptDataLoss {
				res.Dropped = append(res.Dropped, n.Path)
				dropped[n.Path] = true
				logf("pack 缺失，按 --accept-data-loss 丢弃：%s", n.Path)
				continue
			}
			return nil, derr
		}
		ops = append(ops, wire.Op{
			Type: wire.OpAdd, Path: n.Path, Mode: n.Mode, Size: n.Size,
			ModTimeNS: n.ModTimeNS, ContentSHA256: n.ContentSHA256, Slices: newSlices,
		})
	}
	for _, n := range links {
		ops = append(ops, wire.Op{
			Type: wire.OpSymlink, Path: n.Path, Mode: n.Mode, ModTimeNS: n.ModTimeNS, Extra: n.LinkTarget,
		})
	}
	sort.Slice(ops, func(i, j int) bool { return opSortKey(ops[i]) < opSortKey(ops[j]) })

	packs, err := pw.SealAll()
	if err != nil {
		return nil, err
	}
	res.Packs = packs
	for _, p := range packs {
		res.PackBytes += p.Size
	}

	// One journal, seq=1, containing the whole snapshot.
	body := &wire.Journal{
		FormatVersion: wire.JournalFormatVersion,
		Seq:           1,
		TxnID:         txn,
		TSUnix:        now().Unix(),
		Msg:           "compact from seq " + itoa64(chain.LastSeq),
		PrevHash:      journal.GenesisHash,
		Flags:         wire.JournalFlagFinal,
		Kind:          wire.KindCommit,
		Params:        opts.Config.Params(),
		Packs:         packs,
		Dirs:          dirEntries,
		Ops:           ops,
	}
	plain, err := wire.EncodeJournalBody(body)
	if err != nil {
		return nil, apexerr.From(err)
	}
	raw, err := wire.SealJournalFileWithOptions(outKeys.Sub.Journal.Bytes(), 1, outKeys.VaultID[:], plain, opts.Config.CodecOptions())
	if err != nil {
		return nil, apexerr.From(err)
	}
	abs, err := newLayout.AbsPath(newLayout.JournalRelPath(1))
	if err != nil {
		return nil, err
	}
	if err := store.WriteFileDurableAs(newLayout.StagingDir, newLayout.JournalName(1)+".tmp", abs, raw, 0o644); err != nil {
		return nil, err
	}
	res.Seq = 1

	// Verify the new vault end to end before declaring success.
	logf("正在校验新库…")
	newChain, err := journal.Load(newLayout, outKeys.Sub.Journal.Bytes(), outKeys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		return nil, apexerr.From(err).WithScope("新库自检失败，请保留旧库并反馈")
	}
	if err := verifyNewTree(newLayout, outKeys, newChain, files, dropped); err != nil {
		return nil, err
	}

	// New control plane state (only for a new identity; same identity keeps its
	// existing control plane and is told to run rebuild-state).
	if opts.NewIdentity && newMeta != nil {
		db, derr := index.Open(opts.NewVaultDir)
		if derr == nil {
			vid := outKeys.VaultID[:]
			_ = db.SetVaultID(vid)
			sum := sha256.Sum256(raw)
			mac := vaultcrypto.AnchorMAC(outKeys.Sub.Anchor.Bytes(), 1, sum)
			_ = db.PutAnchor(1, sum, mac)
			_ = db.SetLastSeq(1)
			_ = db.MarkExport(now())
			db.Close()
		}
	}
	res.Duration = now().Sub(start)
	return res, nil
}

// repackFile copies one file's verified plaintext into the new packs.
func repackFile(reader *store.PackReader, pw *store.PackWriter, packs map[string]wire.PackRef, n *journal.Node, opts codec.Options) ([]wire.SliceRef, error) {
	if len(n.Slices) == 0 {
		return nil, nil
	}
	out := make([]wire.SliceRef, 0, len(n.Slices))
	for i, ref := range n.Slices {
		if i >= len(n.PackNames) {
			return nil, apexerr.Newf(apexerr.CodeCorrupt, "切片缺少 pack 映射：%s#%d", n.Path, i)
		}
		packName := n.PackNames[i]
		pr, ok := packs[packName]
		if !ok {
			return nil, apexerr.Newf(apexerr.CodeCorrupt, "找不到 pack 指纹：%s", packName)
		}
		h, err := reader.Open(packName, pr.Size)
		if err != nil {
			return nil, err
		}
		plain, err := reader.ReadSlice(h, ref, n.TxnID)
		if err != nil {
			return nil, err
		}
		codecID, payload, cerr := codec.CompressWith(plain, opts)
		if cerr != nil {
			return nil, apexerr.Wrapf(cerr, apexerr.CodeInternal, "压缩失败：%s", n.Path)
		}
		newRef, aerr := pw.Append(codecID, len(plain), payload, sha256.Sum256(plain), uint32(i))
		if aerr != nil {
			return nil, aerr
		}
		out = append(out, newRef)
	}
	return out, nil
}

// verifyNewTree re-reads every kept slice of the new vault (no silent corruption).
func verifyNewTree(layout *store.Layout, keys *vault.Keys, chain *journal.Chain, expected []*journal.Node, dropped map[string]bool) error {
	reader, err := store.NewPackReader(layout, keys.Sub.Storage.Bytes())
	if err != nil {
		return err
	}
	defer reader.Close()
	kept := 0
	for _, n := range expected {
		if dropped[n.Path] {
			continue
		}
		node, ok := chain.Tree.Get(n.Path)
		if !ok {
			return apexerr.Newf(apexerr.CodeCorrupt, "新库缺少文件：%s", n.Path)
		}
		if node.ContentSHA256 != n.ContentSHA256 {
			return apexerr.Newf(apexerr.CodeCorrupt, "新库内容哈希不一致：%s", n.Path)
		}
		for i, ref := range node.Slices {
			pr, ok := chain.Tree.Packs[node.PackNames[i]]
			if !ok {
				return apexerr.Newf(apexerr.CodeCorrupt, "新库缺少 pack：%s", node.PackNames[i])
			}
			h, err := reader.Open(node.PackNames[i], pr.Size)
			if err != nil {
				return err
			}
			if _, err := reader.ReadSlice(h, ref, node.TxnID); err != nil {
				return err
			}
		}
		kept++
	}
	if chain.Tree.Len() < kept {
		return apexerr.Newf(apexerr.CodeCorrupt, "新库节点数异常：%d < %d", chain.Tree.Len(), kept)
	}
	return nil
}

func ensureEmptyDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeUsage, "无法访问输出目录：%s", dir)
	}
	if !info.IsDir() {
		return apexerr.Newf(apexerr.CodeUsage, "输出路径已存在且不是目录：%s", dir)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return apexerr.Wrapf(rerr, apexerr.CodeUsage, "无法读取输出目录：%s", dir)
	}
	if len(entries) != 0 {
		return apexerr.Newf(apexerr.CodeUsage, "输出目录必须为空：%s（已有 %d 个条目）", dir, len(entries)).
			WithScope("compact 不会覆盖已有数据")
	}
	return nil
}

func opSortKey(op wire.Op) string {
	var prefix byte
	switch op.Type {
	case wire.OpMkdir:
		prefix = '0'
	case wire.OpAdd, wire.OpModify:
		prefix = '1'
	case wire.OpSymlink:
		prefix = '2'
	default:
		prefix = '3'
	}
	return string(prefix) + op.Path
}

func itoa64(v uint64) string {
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
