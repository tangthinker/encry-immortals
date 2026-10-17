package cli

import (
	"flag"
	"fmt"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/pipeline"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func cmdBackup(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	source := fs.String("source", "", "源目录（必填，一次只能一个）")
	message := ""
	fs.StringVar(&message, "message", "", "提交信息（等同 git commit -m）")
	fs.StringVar(&message, "m", "", "提交信息（--message 的简写）")
	strict := fs.Bool("strict", false, "全量内容 hash 比对，不依赖 mtime")
	dryRun := fs.Bool("dry-run", false, "只报告将发生的变更，不落盘")
	breakLock := fs.Bool("break-lock", false, "删除 TargetDir/.apex.lock（确认对方已失效时使用）")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	if *source == "" {
		return apexerr.New(apexerr.CodeUsage, "backup 需要 --source <源目录>").
			WithNext("apex backup --source ~/Documents -m '日常增量'")
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
	res, err := pipeline.Backup(pipeline.BackupOptions{
		Layout:      layout,
		Keys:        s.keys,
		Config:      s.cfg,
		DB:          s.db,
		SourceDir:   *source,
		Message:     message,
		Strict:      *strict,
		DryRun:      *dryRun,
		BreakLock:   *breakLock,
		ToolVersion: Version,
		Progress:    s.progress,
	})
	if err != nil {
		return err
	}
	type jsonResult struct {
		Seq          uint64 `json:"seq"`
		Changed      bool   `json:"changed"`
		DryRun       bool   `json:"dry_run"`
		Added        int    `json:"added"`
		Modified     int    `json:"modified"`
		Deleted      int    `json:"deleted"`
		Meta         int    `json:"meta"`
		Dirs         int    `json:"dirs"`
		Links        int    `json:"links"`
		PackBytes    uint64 `json:"pack_bytes"`
		JournalBytes int    `json:"journal_bytes"`
		Truncated    bool   `json:"truncated"`
		Skipped      int    `json:"skipped"`
	}
	doc := jsonResult{
		Seq: res.Seq, Changed: res.Changed, DryRun: *dryRun,
		Added: res.Stats.Added, Modified: res.Stats.Modified, Deleted: res.Stats.Deleted,
		Meta: res.Stats.Meta, Dirs: res.Stats.Dirs, Links: res.Stats.Links,
		PackBytes: res.PackBytes, JournalBytes: res.JournalBytes,
		Truncated: res.Truncated, Skipped: res.Skipped,
	}
	return s.printJSONOrHuman(doc, func() {
		if !res.Changed {
			fmt.Fprintln(s.stdout, "no changes")
			return
		}
		prefix := "已提交"
		if *dryRun {
			prefix = "dry-run（未写入）"
		}
		fmt.Fprintf(s.stdout, "%s seq=%d · ADD %d MODIFY %d DELETE %d META %d DIR %d LINK %d\n",
			prefix, res.Seq, res.Stats.Added, res.Stats.Modified, res.Stats.Deleted,
			res.Stats.Meta, res.Stats.Dirs, res.Stats.Links)
		if *dryRun {
			fmt.Fprintf(s.stdout, "预计 %d 个 pack，%s\n", res.EstimatedPacks, humanBytes(int64(res.EstimatedBytes)))
			return
		}
		fmt.Fprintf(s.stdout, "%d 个 pack · %s · journal %s · 用时 %s\n",
			len(res.Packs), humanBytes(int64(res.PackBytes)), humanBytes(int64(res.JournalBytes)),
			res.Duration.Round(time.Millisecond))
		if res.Truncated {
			fmt.Fprintln(s.stderr, "提示：本次达到 session_max_mib 上限，剩余改动会在下次备份处理。")
		}
	})
}

func cmdNote(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("note", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	message := fs.Arg(0)
	if message == "" {
		return apexerr.New(apexerr.CodeUsage, "用法：apex note \"消息\"")
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
	seq, _, err := pipeline.WriteNote(pipeline.NoteOptions{
		Layout:  layout,
		Keys:    s.keys,
		Params:  s.cfg.Params(),
		Message: message,
		Now:     time.Now,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(s.stdout, "已写入注释 journal seq=%d\n", seq)
	return nil
}

var _ = wire.JournalFormatVersion
