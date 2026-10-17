package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/config"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/pathx"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/testhooks"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

// Overwrite policies (spec 05.6).
const (
	OverwriteNever     = "never"
	OverwriteIfChanged = "if-changed"
	OverwriteAlways    = "always"
)

// ProgressFileName is the resume marker inside the restore destination.
const ProgressFileName = ".apex-restore-progress"

// RestoreOptions drives one restore run.
type RestoreOptions struct {
	Layout               *store.Layout
	Keys                 *vault.Keys
	Config               *config.Config
	DestDir              string
	AtSeq                uint64
	Overwrite            string
	AllowExternalSymlink bool
	RestoreSUID          bool
	DryRun               bool
	Progress             func(format string, args ...any)
	Now                  func() time.Time
}

// RestoreResult reports what one restore did.
type RestoreResult struct {
	Seq      uint64
	Files    int
	Dirs     int
	Links    int
	Bytes    uint64
	Skipped  []string
	Corrupt  []string
	DryRun   bool
	Duration time.Duration
}

type restoreRun struct {
	opts    RestoreOptions
	chain   *journal.Chain
	reader  *store.PackReader
	destDir string
	res     *RestoreResult
	prog    *progressLog
}

// Restore rebuilds the tree at DestDir, replaying journals up to AtSeq.
func Restore(opts RestoreOptions) (*RestoreResult, error) {
	if opts.Overwrite == "" {
		opts.Overwrite = OverwriteNever
	}
	switch opts.Overwrite {
	case OverwriteNever, OverwriteIfChanged, OverwriteAlways:
	default:
		return nil, apexerr.Newf(apexerr.CodeUsage, "--overwrite=%q 非法（never|if-changed|always）", opts.Overwrite)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	start := opts.Now()
	destRoot, err := filepath.Abs(opts.DestDir)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "还原目标路径非法：%s", opts.DestDir)
	}
	res := &RestoreResult{DryRun: opts.DryRun}
	run := &restoreRun{opts: opts, destDir: destRoot, res: res}

	run.logf("正在校验 journal 链…")
	chain, err := journal.Load(opts.Layout, opts.Keys.Sub.Journal.Bytes(), opts.Keys.VaultID[:],
		journal.LoadOptions{TargetSeq: opts.AtSeq})
	if err != nil {
		return nil, err
	}
	run.chain = chain
	res.Seq = chain.LastSeq
	if chain.LastSeq == 0 {
		return nil, apexerr.New(apexerr.CodeUsage, "该 vault 还没有任何提交，无法还原")
	}

	if !opts.DryRun {
		if err := run.prepareDest(); err != nil {
			return nil, err
		}
		prog, err := openProgress(destRoot, chain.LastSeq)
		if err != nil {
			return nil, err
		}
		run.prog = prog
	}
	reader, err := store.NewPackReader(opts.Layout, opts.Keys.Sub.Storage.Bytes())
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	run.reader = reader

	// 1. directories, shallow first
	for _, d := range chain.Tree.Dirs() {
		dest, err := pathx.SafeJoin(destRoot, d.Path)
		if err != nil {
			return nil, apexerr.Newf(apexerr.CodeCorrupt, "还原路径不安全：%s", d.Path).WithErr(err)
		}
		res.Dirs++
		if opts.DryRun {
			continue
		}
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return nil, apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建目录：%s", d.Path)
		}
	}

	// 2. regular file contents
	for _, n := range chain.Tree.Files() {
		dest, err := pathx.SafeJoin(destRoot, n.Path)
		if err != nil {
			return nil, apexerr.Newf(apexerr.CodeCorrupt, "还原路径不安全：%s", n.Path).WithErr(err)
		}
		if run.prog != nil && run.prog.isDone(n.Path) {
			continue
		}
		res.Files++
		if opts.DryRun {
			res.Bytes += n.Size
			continue
		}
		write, skipped, derr := run.shouldWriteFile(dest, n)
		if derr != nil {
			return nil, derr
		}
		if skipped {
			res.Skipped = append(res.Skipped, n.Path)
			run.markDone(n.Path)
			continue
		}
		if !write {
			continue
		}
		if werr := run.writeFile(n, dest); werr != nil {
			if apexerr.CodeOf(werr) == apexerr.CodeIncomplete {
				return nil, werr
			}
			res.Corrupt = append(res.Corrupt, n.Path)
			run.logf("损坏，已跳过：%s（%v）", n.Path, werr)
			continue
		}
		res.Bytes += n.Size
		run.markDone(n.Path)
		// K8: crash after the first file landed, before the rest.
		testhooks.Crash("K8")
	}

	// 3. symlinks last (never write through a link created earlier)
	for _, l := range chain.Tree.Links() {
		dest, err := pathx.SafeJoin(destRoot, l.Path)
		if err != nil {
			return nil, apexerr.Newf(apexerr.CodeCorrupt, "还原路径不安全：%s", l.Path).WithErr(err)
		}
		res.Links++
		if opts.DryRun {
			continue
		}
		if err := run.restoreLink(l, dest); err != nil {
			return nil, err
		}
	}

	// 4. modes, then 5. mtimes deepest first
	if !opts.DryRun {
		if err := run.applyModesAndTimes(); err != nil {
			return nil, err
		}
		if run.prog != nil {
			if err := run.prog.finish(); err != nil {
				return nil, err
			}
		}
	}
	res.Duration = opts.Now().Sub(start)
	return res, nil
}

func (r *restoreRun) logf(format string, args ...any) {
	if r.opts.Progress != nil {
		r.opts.Progress(format, args...)
	}
}

func (r *restoreRun) prepareDest() error {
	info, err := os.Stat(r.destDir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(r.destDir, 0o755); err != nil {
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建还原目录：%s", r.destDir)
		}
		return nil
	}
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeUsage, "无法访问还原目录：%s", r.destDir)
	}
	if !info.IsDir() {
		return apexerr.Newf(apexerr.CodeUsage, "还原目标不是目录：%s", r.destDir)
	}
	entries, err := os.ReadDir(r.destDir)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeUsage, "无法读取还原目录：%s", r.destDir)
	}
	foreign := 0
	for _, e := range entries {
		if e.Name() == ProgressFileName {
			continue
		}
		foreign++
	}
	if foreign > 0 && r.opts.Overwrite == OverwriteNever {
		return apexerr.Newf(apexerr.CodeUsage, "还原目标目录非空：%s", r.destDir).
			WithScope("灾备场景下把数据混进已有目录极易造成误判").
			WithNext("换一个空目录，或用 --overwrite if-changed/always 明确覆盖")
	}
	return nil
}

func (r *restoreRun) markDone(path string) {
	if r.prog == nil {
		return
	}
	if err := r.prog.mark(path); err != nil {
		r.logf("警告：无法写入续解进度：%v", err)
	}
}

// shouldWriteFile decides between write / skip / error per overwrite policy.
func (r *restoreRun) shouldWriteFile(dest string, n *journal.Node) (write, skipped bool, err error) {
	info, lerr := os.Lstat(dest)
	if os.IsNotExist(lerr) {
		return true, false, nil
	}
	if lerr != nil {
		return false, false, apexerr.Wrapf(lerr, apexerr.CodeUsage, "无法读取已存在的目标：%s", n.Path)
	}
	if !info.Mode().IsRegular() {
		if r.opts.Overwrite == OverwriteNever {
			return false, true, nil
		}
		if info.IsDir() {
			return false, false, apexerr.Newf(apexerr.CodeCorrupt,
				"目标路径是一个目录，无法用文件覆盖：%s", n.Path).
				WithNext("手工移走该目录后重试")
		}
		return true, false, nil
	}
	switch r.opts.Overwrite {
	case OverwriteAlways:
		return true, false, nil
	default:
		same, cmpErr := fileMatches(dest, n)
		if cmpErr != nil {
			return false, false, cmpErr
		}
		if same {
			return false, true, nil
		}
		if r.opts.Overwrite == OverwriteNever {
			return false, true, nil
		}
		return true, false, nil
	}
}

func fileMatches(dest string, n *journal.Node) (bool, error) {
	info, err := os.Stat(dest)
	if err != nil {
		return false, nil
	}
	if info.Size() != int64(n.Size) {
		return false, nil
	}
	f, err := os.Open(filepath.Clean(dest))
	if err != nil {
		return false, nil
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, nil
	}
	return bytes.Equal(h.Sum(nil), n.ContentSHA256[:]), nil
}

func (r *restoreRun) writeFile(n *journal.Node, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建父目录：%s", n.Path)
	}
	tmp := dest + ".apex-tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建临时文件：%s", n.Path)
	}
	cleanup := func() {
		f.Close()
		os.Remove(tmp)
	}
	h := sha256.New()
	for i, ref := range n.Slices {
		if i >= len(n.PackNames) {
			cleanup()
			return apexerr.Newf(apexerr.CodeCorrupt, "切片缺少 pack 映射：%s#%d", n.Path, i)
		}
		packName := n.PackNames[i]
		pr, ok := r.chain.Tree.Packs[packName]
		if !ok {
			cleanup()
			return apexerr.Newf(apexerr.CodeCorrupt, "找不到 pack 指纹：%s", packName)
		}
		hnd, oerr := r.reader.Open(packName, pr.Size)
		if oerr != nil {
			cleanup()
			return oerr
		}
		var plain []byte
		var rerr error
		for attempt := 0; attempt < 3; attempt++ {
			plain, rerr = r.reader.ReadSlice(hnd, ref, n.TxnID)
			if rerr == nil {
				break
			}
			time.Sleep(time.Duration(attempt) * 150 * time.Millisecond)
		}
		if rerr != nil {
			cleanup()
			return rerr
		}
		if _, werr := f.Write(plain); werr != nil {
			cleanup()
			return apexerr.Wrapf(werr, apexerr.CodeNoSpace, "写入还原文件失败：%s", n.Path)
		}
		h.Write(plain)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "刷盘失败：%s", n.Path)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "关闭失败：%s", n.Path)
	}
	if !bytes.Equal(h.Sum(nil), n.ContentSHA256[:]) {
		os.Remove(tmp)
		return apexerr.Newf(apexerr.CodeCorrupt,
			"还原出的内容 SHA-256 与 journal 记录不符：%s", n.Path).
			WithNext("执行 apex verify --deep 定位损坏的 pack")
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "原子替换失败：%s", n.Path)
	}
	return nil
}

func (r *restoreRun) restoreLink(l *journal.Node, dest string) error {
	if filepath.IsAbs(l.LinkTarget) && !r.opts.AllowExternalSymlink {
		return apexerr.Newf(apexerr.CodeUnsupported,
			"拒绝还原指向绝对路径的符号链接：%s -> %s", l.Path, l.LinkTarget).
			WithNext("确认信任该 vault 后加 --allow-external-symlink")
	}
	info, err := os.Lstat(dest)
	if err == nil {
		if info.IsDir() {
			return apexerr.Newf(apexerr.CodeCorrupt, "目标路径是一个目录，无法用符号链接覆盖：%s", l.Path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			old, _ := os.Readlink(dest)
			if old == l.LinkTarget {
				r.res.Skipped = append(r.res.Skipped, l.Path)
				return nil
			}
		}
		if r.opts.Overwrite == OverwriteNever {
			r.res.Skipped = append(r.res.Skipped, l.Path)
			return nil
		}
		if err := os.Remove(dest); err != nil {
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法替换已有链接：%s", l.Path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建父目录：%s", l.Path)
	}
	if err := os.Symlink(l.LinkTarget, dest); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建符号链接：%s", l.Path)
	}
	return nil
}

func (r *restoreRun) applyModesAndTimes() error {
	type item struct {
		dest  string
		mode  uint32
		mtime int64
		kind  journal.Kind
	}
	var items []item
	add := func(n *journal.Node) error {
		dest, err := pathx.SafeJoin(r.destDir, n.Path)
		if err != nil {
			return err
		}
		items = append(items, item{dest: dest, mode: n.Mode, mtime: n.ModTimeNS, kind: n.Kind})
		return nil
	}
	for _, n := range r.chain.Tree.Files() {
		if err := add(n); err != nil {
			return err
		}
	}
	for _, n := range r.chain.Tree.Dirs() {
		if err := add(n); err != nil {
			return err
		}
	}
	for _, n := range r.chain.Tree.Links() {
		if err := add(n); err != nil {
			return err
		}
	}
	for _, it := range items {
		if it.kind == journal.KindSymlink {
			continue // chmod follows links; apex does not touch link targets
		}
		mode := it.mode & 0o777
		if r.opts.RestoreSUID {
			mode = it.mode & 0o7777
		}
		if err := os.Chmod(it.dest, os.FileMode(mode)); err != nil && !os.IsNotExist(err) {
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法设置权限：%s", it.dest)
		}
	}
	// Deepest first so parent mtimes are not refreshed afterwards.
	sort.Slice(items, func(i, j int) bool {
		return depthOf(items[i].dest) > depthOf(items[j].dest)
	})
	for _, it := range items {
		if it.kind == journal.KindSymlink {
			continue
		}
		t := time.Unix(0, it.mtime)
		if err := os.Chtimes(it.dest, t, t); err != nil && !os.IsNotExist(err) {
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法设置修改时间：%s", it.dest)
		}
	}
	return nil
}

func depthOf(p string) int {
	n := 0
	for i := 0; i < len(p); i++ {
		if os.IsPathSeparator(p[i]) {
			n++
		}
	}
	return n
}

// progressLog is the append-only resume marker (spec 05.6).
type progressLog struct {
	path string
	f    *os.File
	done map[string]bool
}

type progressRecord struct {
	Seq  uint64 `json:"seq"`
	Path string `json:"path,omitempty"`
}

func openProgress(destRoot string, seq uint64) (*progressLog, error) {
	path := filepath.Join(destRoot, ProgressFileName)
	p := &progressLog{path: path, done: make(map[string]bool)}
	if raw, err := os.ReadFile(path); err == nil {
		for _, line := range bytes.Split(raw, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var rec progressRecord
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			if rec.Path == "" {
				if rec.Seq != seq {
					// A different snapshot: start over.
					return resetProgress(path, seq)
				}
				continue
			}
			if rec.Seq == seq {
				p.done[rec.Path] = true
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建续解进度文件")
	}
	p.f = f
	if len(p.done) == 0 {
		if err := p.write(progressRecord{Seq: seq}); err != nil {
			f.Close()
			return nil, err
		}
	}
	return p, nil
}

func resetProgress(path string, seq uint64) (*progressLog, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	p := &progressLog{path: path, f: f, done: make(map[string]bool)}
	if err := p.write(progressRecord{Seq: seq}); err != nil {
		f.Close()
		return nil, err
	}
	return p, nil
}

func (p *progressLog) write(rec progressRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := p.f.Write(append(raw, '\n')); err != nil {
		return apexerr.Wrap(err, apexerr.CodeNoSpace, "写入续解进度失败")
	}
	return nil
}

func (p *progressLog) isDone(path string) bool { return p.done[path] }

func (p *progressLog) mark(path string) error {
	p.done[path] = true
	return p.write(progressRecord{Seq: 0, Path: path})
}

func (p *progressLog) finish() error {
	if p.f != nil {
		p.f.Sync()
		p.f.Close()
		p.f = nil
	}
	if err := os.Remove(p.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("无法删除续解进度文件：%w", err)
	}
	return nil
}
