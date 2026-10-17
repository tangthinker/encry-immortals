package cli

import (
	"flag"
	"fmt"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/pipeline"
)

func cmdCompact(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("compact", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	out := fs.String("out", "", "新 TargetDir（必填，必须为空或不存在）")
	at := fs.Uint64("at", 0, "以指定 seq 的快照为内容（默认最新）")
	newIdentity := fs.Bool("new-identity", false, "生成新的 vault 身份（新 salt/vault_id，需要重新 export-key）")
	newVault := fs.String("new-vault", "", "--new-identity 时的新控制平面目录")
	dryRun := fs.Bool("dry-run", false, "只报告不写盘")
	acceptLoss := fs.Bool("accept-data-loss", false, "允许跳过 pack 缺失的文件（会在结果中列出）")
	if err := parseInterspersed(fs, args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	if *out == "" {
		return apexerr.New(apexerr.CodeUsage, "compact 需要 --out <新 TargetDir>").
			WithNext("apex compact --out /path/to/new-target")
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
	var newPassword []byte
	if *newIdentity {
		if *newVault == "" {
			return apexerr.New(apexerr.CodeUsage, "--new-identity 需要 --new-vault <新控制平面目录>").
				WithScope("新的 salt 与 vault_id 不能写进 TargetDir（盲盒原则）")
		}
		newPassword, err = a.password(g, "请输入新的主密码：", true)
		if err != nil {
			return err
		}
		defer zero(newPassword)
	}
	res, err := pipeline.Compact(pipeline.CompactOptions{
		Layout:         layout,
		Keys:           s.keys,
		Config:         s.cfg,
		OutDir:         *out,
		NewVaultDir:    *newVault,
		NewIdentity:    *newIdentity,
		NewPassword:    newPassword,
		AtSeq:          *at,
		DryRun:         *dryRun,
		AcceptDataLoss: *acceptLoss,
		ToolVersion:    Version,
		Now:            time.Now,
		Progress:       s.progress,
	})
	if err != nil {
		return err
	}
	type compactJSON struct {
		Seq        uint64   `json:"seq"`
		Files      int      `json:"files"`
		Dirs       int      `json:"dirs"`
		Links      int      `json:"links"`
		Packs      int      `json:"packs"`
		Bytes      uint64   `json:"logical_bytes"`
		PackBytes  uint64   `json:"pack_bytes"`
		Dropped    []string `json:"dropped"`
		NewVaultID string   `json:"new_vault_id,omitempty"`
		ArmorKey   string   `json:"armor_key,omitempty"`
		DryRun     bool     `json:"dry_run"`
	}
	doc := compactJSON{
		Seq: res.Seq, Files: res.Files, Dirs: res.Dirs, Links: res.Links,
		Packs: len(res.Packs), Bytes: res.Bytes, PackBytes: res.PackBytes,
		Dropped: res.Dropped, NewVaultID: res.NewVaultID, ArmorKey: res.ArmorKey, DryRun: *dryRun,
	}
	if err := s.printJSONOrHuman(doc, func() {
		if *dryRun {
			fmt.Fprintf(s.stdout, "dry-run：将写入 %d 个文件 / %d 个目录 / %d 个链接，逻辑大小 %s\n",
				res.Files, res.Dirs, res.Links, humanBytes(int64(res.Bytes)))
			return
		}
		fmt.Fprintf(s.stdout, "已重建新库 seq=%d · 文件 %d 目录 %d 链接 %d · %s in %d packs · 用时 %s\n",
			res.Seq, res.Files, res.Dirs, res.Links, humanBytes(int64(res.PackBytes)),
			len(res.Packs), res.Duration.Round(time.Millisecond))
	}); err != nil {
		return err
	}
	if *newIdentity && res.ArmorKey != "" {
		fmt.Fprintln(s.stdout, "")
		fmt.Fprintln(s.stdout, "== 新库的 Armor Key（旧 Armor Key 对新库无效）==")
		fmt.Fprintln(s.stdout, res.ArmorKey)
	}
	if len(res.Dropped) > 0 {
		msg := fmt.Sprintf("有 %d 个文件因 pack 缺失被丢弃", len(res.Dropped))
		for _, p := range res.Dropped {
			msg += "\n  - " + p
		}
		return apexerr.New(apexerr.CodeIncomplete, msg).
			WithNext("确认这些文件可以从别处找回后再删除旧库")
	}
	if !*dryRun {
		fmt.Fprintln(s.stderr, "旧库未被改动。切换前请：1) 把 config 的 target_dir 指向新目录；2) 执行 apex rebuild-state；3) 验证通过后再手工删除旧目录（建议保留 ≥30 天）。")
	}
	return nil
}
