package pipeline

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	"github.com/tangthinker/encry-immortals/internal/config"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/index"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/lock"
	"github.com/tangthinker/encry-immortals/internal/pathx"
	"github.com/tangthinker/encry-immortals/internal/scan"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// ErrStale is returned when a source file changed while it was being read.
var ErrStale = errors.New("pipeline: source changed during read")

// BackupOptions drives one backup run (spec 05.1 S0–S7).
type BackupOptions struct {
	Layout      *store.Layout
	Keys        *vault.Keys
	Config      *config.Config
	DB          *index.DB // optional cache/anchor store
	SourceDir   string
	Message     string
	Strict      bool
	DryRun      bool
	BreakLock   bool
	ToolVersion string
	Now         func() time.Time
	Progress    func(format string, args ...any)
}

// BackupResult reports what one run did.
type BackupResult struct {
	Seq            uint64
	Changed        bool
	Stats          Stats
	Packs          []wire.PackRef
	PackBytes      uint64
	JournalBytes   int
	StagingSwept   int
	Truncated      bool
	Skipped        int
	EstimatedOps   int
	EstimatedPacks int
	EstimatedBytes uint64
	Duration       time.Duration
}

type backupRun struct {
	opts      BackupOptions
	cfg       *config.Config
	now       func() time.Time
	progress  func(format string, args ...any)
	sourceDir string
}

func (r *backupRun) logf(format string, args ...any) {
	if r.progress != nil {
		r.progress(format, args...)
	}
}

// Backup executes one incremental commit.
func Backup(opts BackupOptions) (*BackupResult, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	run := &backupRun{opts: opts, cfg: opts.Config, now: now, progress: opts.Progress}
	if run.cfg == nil {
		run.cfg = config.Default()
	}
	res := &BackupResult{}
	start := now()

	// S0: preflight ----------------------------------------------------------
	if err := opts.Layout.Ensure(); err != nil {
		return nil, err
	}
	if err := opts.Layout.ValidateTopLevel(); err != nil {
		return nil, err
	}
	if err := opts.Layout.ValidateStagingVolume(); err != nil {
		return nil, err
	}
	sourceRoot, err := filepath.Abs(opts.SourceDir)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "源目录路径非法：%s", opts.SourceDir)
	}
	if info, serr := os.Stat(sourceRoot); serr != nil || !info.IsDir() {
		return nil, apexerr.Newf(apexerr.CodeUsage, "源目录不可用：%s", sourceRoot)
	}
	overlap, err := pathx.Overlap(sourceRoot, opts.Layout.TargetDir)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法判断源目录与 TargetDir 是否重叠")
	}
	if overlap {
		return nil, apexerr.New(apexerr.CodeUsage, "源目录与 TargetDir 重叠").
			WithScope("备份会把自己写出的 pack 再次备份，形成无限自指").
			WithNext("把 TargetDir 移出源目录（或反之）")
	}
	run.sourceDir = sourceRoot

	removed, _, serr := store.SweepStaging(opts.Layout.StagingDir, now().Unix(), 24*3600)
	if serr != nil {
		return nil, serr
	}
	res.StagingSwept = removed
	if removed > 0 {
		run.logf("已清理 %d 个超过 24h 的暂存残留", removed)
	}

	if opts.BreakLock {
		if err := lock.BreakTargetLock(opts.Layout.TargetDir); err != nil {
			return nil, err
		}
	}
	tl, err := lock.AcquireTargetLock(opts.Layout.TargetDir, lock.NewTargetInfo(opts.ToolVersion))
	if err != nil {
		return nil, err
	}
	defer tl.Release()

	// S1: replay + scan + diff ----------------------------------------------
	run.logf("正在校验 journal 链…")
	chain, err := journal.Load(opts.Layout, opts.Keys.Sub.Journal.Bytes(), opts.Keys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		return nil, err
	}
	run.logf("现有提交 %d 次，正在扫描源目录…", chain.LastSeq)
	scanned, err := scan.Scan(scan.Options{
		Root:                 sourceRoot,
		Excludes:             run.cfg.Scan.Exclude,
		FollowHardlinks:      run.cfg.Scan.FollowHardlinks == "split",
		SparseMaxBytes:       run.cfg.Scan.SparseMaxBytes,
		AllowExternalSymlink: false,
	})
	if err != nil {
		return nil, err
	}
	diff, err := ComputeDiff(chain.Tree, scanned, opts.Strict || run.cfg.Scan.Mode == "strict", run.hashSourceFile)
	if err != nil {
		return nil, err
	}
	res.Stats = diff.Stats

	if !diff.Stats.Changed() {
		res.Duration = now().Sub(start)
		run.logf("no changes")
		return res, nil
	}
	if opts.DryRun {
		return run.dryRun(diff, res, start)
	}

	// S2/S3: write packs -----------------------------------------------------
	txnID, err := vaultcrypto.RandomBytes(16)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法生成 txn_id")
	}
	var txn [16]byte
	copy(txn[:], txnID)

	pw, err := store.NewPackWriter(opts.Layout, opts.Keys.Sub.Storage.Bytes(), txn,
		run.cfg.Storage.PackMaxBytes, 100_000)
	if err != nil {
		return nil, err
	}
	defer pw.Abort()

	sessionCap := run.cfg.Storage.SessionMaxMiB << 20
	var written uint64
	kept := make([]wire.Op, 0, len(diff.Ops))
	for i := range diff.Ops {
		op := diff.Ops[i]
		if op.Type != wire.OpAdd && op.Type != wire.OpModify {
			kept = append(kept, op)
			continue
		}
		if sessionCap > 0 && written+op.Size > sessionCap {
			res.Truncated = true
			run.logf("已达到单次会话上限 %d MiB，其余改动留待下次备份", run.cfg.Storage.SessionMaxMiB)
			continue
		}
		entry := scan.Entry{Path: op.Path, Size: int64(op.Size), Kind: scan.KindFile}
		slices, sum, werr := run.writeFileWithRetry(pw, entry, op.Mode, op.ModTimeNS)
		if errors.Is(werr, ErrStale) {
			res.Skipped++
			run.logf("跳过（读取期间被修改）：%s", op.Path)
			continue
		}
		if werr != nil {
			return nil, werr
		}
		op.Slices = slices
		op.ContentSHA256 = sum
		kept = append(kept, op)
		written += op.Size
	}
	diff.Ops = kept
	if len(diff.Ops) == 0 {
		res.Duration = now().Sub(start)
		return res, nil
	}

	packs, err := pw.SealAll()
	if err != nil {
		return nil, err
	}
	for _, p := range packs {
		res.PackBytes += p.Size
	}
	res.Packs = packs

	// S4/S5/S6: journal commit ----------------------------------------------
	seq, journalSHA, journalBytes, err := run.commitJournal(chain, diff, packs, txn)
	if err != nil {
		return nil, err
	}
	res.Seq = seq
	res.Changed = true
	res.JournalBytes = journalBytes

	// S7: local state --------------------------------------------------------
	if opts.DB != nil {
		if err := run.updateState(opts.DB, diff, seq, journalSHA); err != nil {
			// The commit is already durable; a stale cache only costs a rescan.
			run.logf("警告：state.db 更新失败（下次备份会重新计算差异）：%v", err)
		}
	}
	res.Duration = now().Sub(start)
	run.logf("已提交 seq=%d（本地完成）。云端同步由网盘客户端负责，可用 apex status 对比本地与云端条目数。", seq)
	return res, nil
}

func (r *backupRun) dryRun(diff *Diff, res *BackupResult, start time.Time) (*BackupResult, error) {
	res.EstimatedOps = len(diff.Ops)
	var bytes uint64
	for _, op := range diff.Ops {
		if op.Type == wire.OpAdd || op.Type == wire.OpModify {
			bytes += op.Size
		}
	}
	res.EstimatedBytes = bytes
	// Upper bound: one envelope per slice plus header/footer per pack.
	slices := bytes / r.cfg.Storage.SlicePlainBytes
	if bytes%r.cfg.Storage.SlicePlainBytes != 0 {
		slices++
	}
	perPack := r.cfg.Storage.PackMaxBytes
	res.EstimatedPacks = int(bytes/perPack) + 1
	res.Changed = true // "would change"; no journal was written
	res.Duration = r.now().Sub(start)
	return res, nil
}

func (r *backupRun) hashSourceFile(rel string) ([32]byte, error) {
	var zero [32]byte
	abs, err := pathx.SafeJoin(r.sourceDir, rel)
	if err != nil {
		return zero, err
	}
	f, err := os.Open(filepath.Clean(abs))
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return zero, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

type statSig struct {
	size    int64
	mtimeNS int64
	ctimeNS int64
	ino     uint64
	dev     uint64
}

func statSigOf(abs string) (statSig, error) {
	fi, err := os.Lstat(abs)
	if err != nil {
		return statSig{}, err
	}
	sig := statSig{size: fi.Size(), mtimeNS: fi.ModTime().UnixNano(), ctimeNS: scan.CtimeNS(fi)}
	if ino, dev, _, _, ok := scan.SysInfo(fi); ok {
		sig.ino, sig.dev = ino, dev
	}
	return sig, nil
}

func (r *backupRun) writeFileWithRetry(pw *store.PackWriter, e scan.Entry, mode uint32, modTimeNS int64) ([]wire.SliceRef, [32]byte, error) {
	delays := []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, time.Second}
	for attempt := 0; ; attempt++ {
		slices, sum, err := r.writeFileOnce(pw, e)
		if err == nil {
			return slices, sum, nil
		}
		if !errors.Is(err, ErrStale) {
			return nil, sum, err
		}
		switch r.cfg.OnChange.Strategy {
		case "skip":
			return nil, sum, ErrStale
		case "fail":
			return nil, sum, apexerr.Newf(apexerr.CodeUnsupported, "读取期间源文件发生变化：%s", e.Path).
				WithScope("拒绝把不一致的内容写入快照（策略 on_change_during_read=fail）")
		default:
			if attempt >= len(delays) {
				return nil, sum, apexerr.Newf(apexerr.CodeUnsupported, "读取期间源文件反复变化：%s", e.Path).
					WithNext("关闭正在写入该文件的程序后重试，或改用 --exclude")
			}
			time.Sleep(delays[attempt])
			r.logf("源文件在读取期间变化，重试第 %d 次：%s", attempt+1, e.Path)
		}
	}
}

// writeFileOnce streams one file into slices with before/after stat comparison.
func (r *backupRun) writeFileOnce(pw *store.PackWriter, e scan.Entry) ([]wire.SliceRef, [32]byte, error) {
	var zero [32]byte
	abs, err := pathx.SafeJoin(r.sourceDir, e.Path)
	if err != nil {
		return nil, zero, err
	}
	if e.Size == 0 {
		return nil, sha256.Sum256(nil), nil
	}
	before, err := statSigOf(abs)
	if err != nil {
		return nil, zero, err
	}
	chunkSize := int64(r.cfg.Storage.SlicePlainBytes)
	if e.Size <= int64(r.cfg.Storage.SmallFileBytes) {
		chunkSize = e.Size
	}
	if chunkSize <= 0 {
		chunkSize = int64(r.cfg.Storage.SlicePlainBytes)
	}
	buf := make([]byte, chunkSize)
	f, err := os.Open(filepath.Clean(abs))
	if err != nil {
		return nil, zero, apexerr.Wrapf(err, apexerr.CodeUnsupported, "无法打开源文件：%s", e.Path)
	}
	defer f.Close()
	h := sha256.New()
	var slices []wire.SliceRef
	for index := uint32(0); ; index++ {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			chunk := buf[:n]
			h.Write(chunk)
			codecID, payload, cerr := codec.Compress(chunk)
			if cerr != nil {
				return nil, zero, apexerr.Wrapf(cerr, apexerr.CodeInternal, "压缩失败：%s", e.Path)
			}
			sum := sha256.Sum256(chunk)
			ref, aerr := pw.Append(codecID, len(chunk), payload, sum, index)
			if aerr != nil {
				return nil, zero, aerr
			}
			slices = append(slices, ref)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, zero, apexerr.Wrapf(rerr, apexerr.CodeUnsupported, "读取源文件失败：%s", e.Path)
		}
	}
	after, err := statSigOf(abs)
	if err != nil {
		return nil, zero, ErrStale
	}
	if before != after {
		return nil, zero, ErrStale
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return slices, sum, nil
}

// commitJournal writes one or more journal files (spec 04.6 split) and returns
// the last sequence, its ciphertext SHA-256 and the total bytes written.
func (r *backupRun) commitJournal(chain *journal.Chain, diff *Diff, packs []wire.PackRef, txn [16]byte) (uint64, [32]byte, int, error) {
	var zero [32]byte
	maxSeq, err := r.opts.Layout.MaxSeq()
	if err != nil {
		return 0, zero, 0, err
	}
	if maxSeq != chain.LastSeq {
		return 0, zero, 0, apexerr.Newf(apexerr.CodeLocked,
			"journal 链在本次运行期间发生了变化：内存 seq=%d，磁盘 seq=%d", chain.LastSeq, maxSeq).
			WithScope("同一 TargetDir 只允许一个写者（I15）").
			WithNext("确认没有其他 apex 进程或主机在写入后重试")
	}
	seq := maxSeq + 1
	prev := journal.GenesisHash
	if chain.LastSeq > 0 {
		prev = chain.LastSHA
	}
	chunks := chunkOps(diff.Ops, wire.MaxOpsPerJournal)
	if len(chunks) == 0 {
		chunks = [][]wire.Op{nil}
	}
	var (
		lastSeq  uint64
		lastSHA  [32]byte
		totalLen int
	)
	for i, chunk := range chunks {
		flags := uint8(0)
		if i == len(chunks)-1 {
			flags = wire.JournalFlagFinal
		}
		j := &wire.Journal{
			FormatVersion: wire.JournalFormatVersion,
			Seq:           seq + uint64(i),
			TxnID:         txn,
			TSUnix:        r.now().Unix(),
			Msg:           r.opts.Message,
			PrevHash:      prev,
			Flags:         flags,
			Kind:          wire.KindCommit,
			Params:        r.cfg.Params(),
			Packs:         packs,
			Ops:           chunk,
		}
		if i == 0 {
			j.Dirs = diff.Dirs
		}
		body, err := wire.EncodeJournalBody(j)
		if err != nil {
			return 0, zero, 0, apexerr.From(err)
		}
		raw, err := wire.SealJournalFile(r.opts.Keys.Sub.Journal.Bytes(), j.Seq, r.opts.Keys.VaultID[:], body)
		if err != nil {
			return 0, zero, 0, apexerr.From(err)
		}
		abs, err := r.opts.Layout.AbsPath(r.opts.Layout.JournalRelPath(j.Seq))
		if err != nil {
			return 0, zero, 0, err
		}
		if err := store.WriteFileDurableAs(r.opts.Layout.StagingDir,
			r.opts.Layout.JournalName(j.Seq)+".tmp", abs, raw, 0o644); err != nil {
			return 0, zero, 0, err
		}
		prev = sha256.Sum256(raw)
		lastSeq = j.Seq
		lastSHA = prev
		totalLen += len(raw)
	}
	return lastSeq, lastSHA, totalLen, nil
}

func chunkOps(ops []wire.Op, max int) [][]wire.Op {
	if max <= 0 {
		max = wire.MaxOpsPerJournal
	}
	var out [][]wire.Op
	for len(ops) > max {
		out = append(out, ops[:max])
		ops = ops[max:]
	}
	if len(ops) > 0 || len(out) == 0 {
		out = append(out, ops)
	}
	return out
}

// updateState refreshes state.db after a successful commit (S7).
func (r *backupRun) updateState(db *index.DB, diff *Diff, seq uint64, journalSHA [32]byte) error {
	pathKey := r.opts.Keys.Sub.Path.Bytes()
	for _, op := range diff.Ops {
		hm := vaultcrypto.PathHMAC(pathKey, []byte(op.Path))
		switch op.Type {
		case wire.OpAdd, wire.OpModify:
			if err := db.PutEntry(index.Entry{
				PathHMAC: hm, Size: int64(op.Size), MtimeNS: op.ModTimeNS,
				ContentSHA256: op.ContentSHA256, LastSeq: seq,
			}); err != nil {
				return err
			}
		case wire.OpMeta:
			if err := db.PutEntry(index.Entry{
				PathHMAC: hm, Size: int64(op.Size), MtimeNS: op.ModTimeNS,
				ContentSHA256: op.ContentSHA256, LastSeq: seq,
			}); err != nil {
				return err
			}
		case wire.OpDelete:
			if err := db.DeleteEntry(hm); err != nil {
				return err
			}
			if err := db.DeleteDir(hm); err != nil {
				return err
			}
		case wire.OpMkdir:
			if err := db.PutDir(index.Dir{PathHMAC: hm, Mode: op.Mode, LastSeq: seq}); err != nil {
				return err
			}
		case wire.OpRmdir:
			if err := db.DeleteDir(hm); err != nil {
				return err
			}
		}
	}
	if err := db.SetLastSeq(seq); err != nil {
		return err
	}
	mac := vaultcrypto.AnchorMAC(r.opts.Keys.Sub.Anchor.Bytes(), seq, journalSHA)
	return db.PutAnchor(seq, journalSHA, mac)
}

// EstimateOps is a small helper for dry-run output.
func EstimateOps(d *Diff) string {
	return fmt.Sprintf("ADD=%d MODIFY=%d DELETE=%d META=%d DIR=%d LINK=%d",
		d.Stats.Added, d.Stats.Modified, d.Stats.Deleted, d.Stats.Meta, d.Stats.Dirs, d.Stats.Links)
}
