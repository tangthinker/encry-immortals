package cli

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/pipeline"
	"github.com/tangthinker/encry-immortals/internal/store"
)

func cmdRestore(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	at := fs.Uint64("at", 0, "还原到指定 seq（默认最新）")
	overwrite := fs.String("overwrite", pipeline.OverwriteNever, "never|if-changed|always")
	allowExternal := fs.Bool("allow-external-symlink", false, "允许还原指向绝对路径的符号链接")
	restoreSUID := fs.Bool("restore-suid", false, "还原 setuid/setgid 位")
	waitPacks := fs.String("wait-for-packs", "", "等待缺失 pack 同步完成的最长时间（如 120s / 5m）")
	dryRun := fs.Bool("dry-run", false, "只统计不写盘")
	if err := parseInterspersed(fs, args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	dest := fs.Arg(0)
	if dest == "" {
		return apexerr.New(apexerr.CodeUsage, "用法：apex restore <DestDir> [--at <seq>]").
			WithNext("建议把 DestDir 指向一个空目录或尚不存在的目录")
	}
	s, err := a.openSession(g, true)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := requireTarget(s.cfg); err != nil {
		return err
	}
	layout, err := newLayout(s.cfg)
	if err != nil {
		return err
	}
	wait, err := parseWaitDuration(*waitPacks)
	if err != nil {
		return err
	}
	res, err := pipeline.Restore(pipeline.RestoreOptions{
		Layout:               layout,
		Keys:                 s.keys,
		Config:               s.cfg,
		DestDir:              dest,
		AtSeq:                *at,
		Overwrite:            *overwrite,
		WaitForPacks:         wait,
		AllowExternalSymlink: *allowExternal,
		RestoreSUID:          *restoreSUID,
		DryRun:               *dryRun,
		Progress:             s.progress,
	})
	if err != nil {
		return err
	}
	type jsonResult struct {
		Seq     uint64   `json:"seq"`
		Files   int      `json:"files"`
		Dirs    int      `json:"dirs"`
		Links   int      `json:"links"`
		Bytes   uint64   `json:"bytes"`
		Skipped []string `json:"skipped"`
		Corrupt []string `json:"corrupt"`
		DryRun  bool     `json:"dry_run"`
	}
	doc := jsonResult{
		Seq: res.Seq, Files: res.Files, Dirs: res.Dirs, Links: res.Links,
		Bytes: res.Bytes, Skipped: res.Skipped, Corrupt: res.Corrupt, DryRun: *dryRun,
	}
	if err := s.printJSONOrHuman(doc, func() {
		prefix := "已还原"
		if *dryRun {
			prefix = "dry-run（未写入）"
		}
		fmt.Fprintf(s.stdout, "%s seq=%d · 文件 %d 目录 %d 链接 %d · %s · 用时 %s\n",
			prefix, res.Seq, res.Files, res.Dirs, res.Links, humanBytes(int64(res.Bytes)),
			res.Duration.Round(time.Millisecond))
		if len(res.Skipped) > 0 {
			fmt.Fprintf(s.stderr, "跳过 %d 个条目（已存在且策略为 %s）\n", len(res.Skipped), *overwrite)
		}
	}); err != nil {
		return err
	}
	if len(res.Corrupt) > 0 {
		msg := fmt.Sprintf("有 %d 个文件因数据损坏未能还原", len(res.Corrupt))
		for _, p := range res.Corrupt {
			msg += "\n  - " + p
		}
		return apexerr.New(apexerr.CodeCorrupt, msg).
			WithNext("执行 apex verify --deep 定位损坏的 pack")
	}
	return nil
}

func cmdLs(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	at := fs.Uint64("at", 0, "以指定 seq 的视角列出")
	if err := parseInterspersed(fs, args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	prefix := fs.Arg(0)
	s, err := a.openSession(g, true)
	if err != nil {
		return err
	}
	defer s.Close()
	layout, err := newLayout(s.cfg)
	if err != nil {
		return err
	}
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:],
		journal.LoadOptions{TargetSeq: *at})
	if err != nil {
		return err
	}
	type item struct {
		Path      string `json:"path"`
		Kind      string `json:"kind"`
		Mode      uint32 `json:"mode"`
		Size      uint64 `json:"size"`
		ModTimeNS int64  `json:"modtime_ns"`
		Target    string `json:"target,omitempty"`
	}
	var items []item
	for _, n := range chain.Tree.Snapshot() {
		if prefix != "" && n.Path != prefix && !hasPrefixDir(n.Path, prefix) {
			continue
		}
		kind := "file"
		switch n.Kind {
		case journal.KindDir:
			kind = "dir"
		case journal.KindSymlink:
			kind = "symlink"
		}
		items = append(items, item{Path: n.Path, Kind: kind, Mode: n.Mode, Size: n.Size, ModTimeNS: n.ModTimeNS, Target: n.LinkTarget})
	}
	return s.printJSONOrHuman(items, func() {
		for _, it := range items {
			switch it.Kind {
			case "dir":
				fmt.Fprintf(s.stdout, "d %s %-8s %s\n", modeString(it.Mode), "-", it.Path)
			case "symlink":
				fmt.Fprintf(s.stdout, "l %s %-8s %s -> %s\n", modeString(it.Mode), "-", it.Path, it.Target)
			default:
				fmt.Fprintf(s.stdout, "- %s %-8s %s\n", modeString(it.Mode), humanBytes(int64(it.Size)), it.Path)
			}
		}
	})
}

func hasPrefixDir(path, prefix string) bool {
	return len(path) > len(prefix) && path[:len(prefix)] == prefix && path[len(prefix)] == '/'
}

func cmdCat(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("cat", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	at := fs.Uint64("at", 0, "读取指定 seq 的版本")
	if err := parseInterspersed(fs, args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	target := fs.Arg(0)
	if target == "" {
		return apexerr.New(apexerr.CodeUsage, "用法：apex cat <path> [--at <seq>]")
	}
	s, err := a.openSession(g, true)
	if err != nil {
		return err
	}
	defer s.Close()
	layout, err := newLayout(s.cfg)
	if err != nil {
		return err
	}
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:],
		journal.LoadOptions{TargetSeq: *at})
	if err != nil {
		return err
	}
	node, ok := chain.Tree.Get(target)
	if !ok {
		return apexerr.Newf(apexerr.CodeUsage, "快照中不存在该路径：%s", target)
	}
	if node.Kind != journal.KindFile {
		return apexerr.Newf(apexerr.CodeUsage, "该路径不是普通文件：%s", target)
	}
	if len(node.Slices) == 0 {
		return nil
	}
	reader, err := store.NewPackReader(layout, s.keys.Sub.Storage.Bytes())
	if err != nil {
		return err
	}
	defer reader.Close()
	for i, ref := range node.Slices {
		packName := node.PackNames[i]
		pr, ok := chain.Tree.Packs[packName]
		if !ok {
			return apexerr.Newf(apexerr.CodeCorrupt, "缺少 pack 指纹：%s", packName)
		}
		h, err := reader.Open(packName, pr.Size)
		if err != nil {
			return err
		}
		plain, err := reader.ReadSlice(h, ref, node.TxnID)
		if err != nil {
			return err
		}
		if _, err := s.stdout.Write(plain); err != nil {
			return apexerr.Wrap(err, apexerr.CodeInternal, "写入 stdout 失败")
		}
	}
	return nil
}

var _ = os.Stdout

// parseWaitDuration accepts "120s", "5m" or a bare number of seconds.
func parseWaitDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, apexerr.New(apexerr.CodeUsage, "--wait-for-packs 不能为负")
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, apexerr.Newf(apexerr.CodeUsage, "--wait-for-packs 取值非法：%q", s).
			WithNext("使用 120s / 5m 这类写法")
	}
	return d, nil
}
