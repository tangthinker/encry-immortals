package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/armor"
	"github.com/tangthinker/encry-immortals/internal/config"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/index"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/lock"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

func cmdVersion(a *App, g *globalFlags, args []string) error {
	fmt.Fprintf(a.Stdout, "apex %s\n", Version)
	return nil
}

func cmdInit(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	join := fs.String("join", "", "加入已有 TargetDir（之后执行 import-key）")
	acceptWeak := fs.Bool("accept-weak-password", false, "明确接受弱主密码的风险")
	threads := fs.Int("threads", 0, "Argon2 线程数（默认 min(4, NumCPU)）")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	cfg, err := config.Load(g.configPath)
	if err != nil {
		return err
	}
	vaultDir := g.vaultDir
	if vaultDir == "" {
		vaultDir = cfg.Vault.Dir
	}
	if err := os.MkdirAll(vaultDir, vault.DirPerm); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建控制平面目录：%s", vaultDir)
	}
	lk, err := lock.AcquireControl(vaultDir)
	if err != nil {
		return err
	}
	defer lk.Release()

	if *join != "" {
		target, err := filepath.Abs(*join)
		if err != nil {
			return apexerr.Wrap(err, apexerr.CodeUsage, "TargetDir 路径非法")
		}
		if info, serr := os.Stat(target); serr != nil || !info.IsDir() {
			return apexerr.Newf(apexerr.CodeUsage, "TargetDir 不存在或不是目录：%s", target)
		}
		pending := filepath.Join(vaultDir, "pending-target")
		if err := os.WriteFile(pending, []byte(target+"\n"), vault.FilePerm); err != nil {
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法记录待加入的 TargetDir")
		}
		fmt.Fprintf(a.Stdout, "已登记待加入的 TargetDir：%s\n", target)
		fmt.Fprintln(a.Stdout, "下一步：apex import-key 并粘贴 Armor Key（来自原机器）。")
		return nil
	}
	if _, err := os.Stat(filepath.Join(vaultDir, vault.MetaFileName)); err == nil {
		return apexerr.Newf(apexerr.CodeUsage, "该控制平面已初始化：%s", vaultDir).
			WithNext("若要加入另一台机器的库，请用 apex init --join <TargetDir>")
	}
	pw, err := a.password(g, "请输入主密码：", true)
	if err != nil {
		return err
	}
	defer zero(pw)
	var threadCount uint8
	if *threads > 0 {
		threadCount = uint8(*threads)
	}
	res, err := vault.Init(vaultDir, vault.InitOptions{
		Password:    pw,
		Threads:     threadCount,
		Now:         time.Now(),
		Force:       *acceptWeak,
		ToolVersion: Version,
	})
	if err != nil {
		return err
	}
	armorStr, err := res.Meta.Armor()
	if err != nil {
		return err
	}
	if db, derr := index.Open(vaultDir); derr == nil {
		if vid, verr := res.Meta.VaultIDBytes(); verr == nil {
			_ = db.SetVaultID(vid)
		}
		_ = db.MarkExport(time.Now())
		db.Close()
	}
	out := a.Stdout
	fmt.Fprintf(out, "已创建 vault：%s\n", vaultDir)
	fmt.Fprintf(out, "vault_id  %s\n", res.Meta.VaultID)
	fmt.Fprintf(out, "KDF       argon2id t=%d m=%d KiB p=%d k=%d\n",
		res.Params.Time, res.Params.MemoryKiB, res.Params.Threads, res.Params.KeyLen)
	fmt.Fprintf(out, "内存峰值  约 %d MiB（解锁时）\n", res.Params.MemoryKiB/1024)
	if res.Strength.RequiresConfirmation() {
		fmt.Fprintf(out, "警告      主密码强度不足：%s\n", strings.Join(res.Strength.Reasons, "；"))
	}
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "== Armor Key（单行版，存进密码管理器）==")
	fmt.Fprintln(out, armorStr)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "== Armor Key（分组版，可打印/手抄）==")
	fmt.Fprintln(out, armor.FormatGrouped(armorStr))
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "重要：主密码不可更改；忘记即永久无法恢复。")
	fmt.Fprintf(out, "恢复须知已写入：%s\n", filepath.Join(vaultDir, vault.RecoveryFileName))
	return nil
}

func cmdExportKey(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("export-key", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	s, err := a.openSession(g, false)
	if err != nil {
		return err
	}
	defer s.Close()
	armorStr, err := s.meta.Armor()
	if err != nil {
		return err
	}
	if err := s.db.MarkExport(time.Now()); err != nil {
		s.progress("警告：无法记录导出时间：%v", err)
	}
	return s.printJSONOrHuman(
		map[string]string{"armor": armorStr, "grouped": armor.FormatGrouped(armorStr)},
		func() {
			fmt.Fprintln(s.stdout, "== 单行版（密码管理器）==")
			fmt.Fprintln(s.stdout, armorStr)
			fmt.Fprintln(s.stdout, "")
			fmt.Fprintln(s.stdout, "== 分组版（打印/手抄，每 5 字符一组）==")
			fmt.Fprintln(s.stdout, armor.FormatGrouped(armorStr))
			fmt.Fprintln(s.stdout, "")
			fmt.Fprintln(s.stderr, "提示：该字符串只含盐与 KDF 参数，不含密钥；请与主密码分开存放。")
		})
}

func cmdImportKey(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("import-key", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	keyFile := fs.String("key-file", "", "从文件读取 Armor Key（默认从 stdin 读取）")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	cfg, err := config.Load(g.configPath)
	if err != nil {
		return err
	}
	vaultDir := g.vaultDir
	if vaultDir == "" {
		vaultDir = cfg.Vault.Dir
	}
	if err := os.MkdirAll(vaultDir, vault.DirPerm); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建控制平面目录：%s", vaultDir)
	}
	var raw []byte
	if *keyFile != "" {
		raw, err = os.ReadFile(*keyFile)
	} else {
		raw, err = io.ReadAll(a.Stdin)
	}
	if err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "无法读取 Armor Key")
	}
	meta, err := vault.ParseArmorString(string(raw))
	if err != nil {
		return err
	}
	lk, err := lock.AcquireControl(vaultDir)
	if err != nil {
		return err
	}
	defer lk.Release()
	if err := meta.Save(vaultDir); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "已导入 vault.meta（vault_id %s）\n", meta.VaultID)
	if pending, perr := os.ReadFile(filepath.Join(vaultDir, "pending-target")); perr == nil {
		fmt.Fprintf(a.Stdout, "已登记的 TargetDir：%s\n", strings.TrimSpace(string(pending)))
		os.Remove(filepath.Join(vaultDir, "pending-target"))
	}
	fmt.Fprintln(a.Stdout, "下一步：apex verify --size 检查数据完整性，然后 apex restore <DestDir>。")
	return nil
}

func cmdStatus(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	clearUnverified := fs.Bool("clear-unverified", false, "清除 UNVERIFIED 标记")
	checkChain := fs.Bool("chain", false, "解锁并计算 packs.referenced/orphan/missing、校验锚点（需要主密码）")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	s, err := a.openSession(g, false)
	if err != nil {
		return err
	}
	defer s.Close()
	if *clearUnverified {
		if err := s.db.SetMeta(index.MetaUnverified, ""); err != nil {
			return err
		}
	}
	layout, err := newLayout(s.cfg)
	if err != nil {
		return err
	}
	packs, err := layout.ListPacks()
	if err != nil {
		return err
	}
	journals, err := layout.ListJournals()
	if err != nil {
		return err
	}
	var packBytes, journalBytes int64
	for _, rel := range packs {
		abs, err := layout.AbsPath(rel)
		if err != nil {
			continue
		}
		if info, err := os.Stat(abs); err == nil {
			packBytes += info.Size()
		}
	}
	for _, seq := range journals {
		abs, err := layout.AbsPath(layout.JournalRelPath(seq))
		if err != nil {
			continue
		}
		if info, err := os.Stat(abs); err == nil {
			journalBytes += info.Size()
		}
	}
	stagingEntries, _ := os.ReadDir(layout.StagingDir)
	var stagingBytes int64
	for _, e := range stagingEntries {
		if info, ierr := e.Info(); ierr == nil {
			stagingBytes += info.Size()
		}
	}
	lastSeq, _ := s.db.LastSeq()
	anchor, hasAnchor, _ := s.db.LatestAnchor()
	unverified, _, _ := s.db.Meta(index.MetaUnverified)
	drill, _, _ := s.db.Meta(index.MetaLastDrillUnix)
	export, _, _ := s.db.Meta(index.MetaLastExportUnix)

	anchorShort := ""
	verified := false
	if hasAnchor {
		anchorShort = shortAnchor(anchor.MAC)
		verified = anchor.Seq == lastSeq && lastSeq > 0
	}
	warnings := []string{}
	if unverified != "" {
		warnings = append(warnings, "上次恢复未经回滚校验（UNVERIFIED）")
	}
	if len(stagingEntries) > 0 {
		warnings = append(warnings, fmt.Sprintf("暂存区有 %d 个残留（云端可能看到残片）", len(stagingEntries)))
	}
	if export == "" {
		warnings = append(warnings, "从未执行 export-key")
	}
	if drill == "" {
		warnings = append(warnings, "从未做过恢复演练")
	}
	if len(packs) == 0 {
		warnings = append(warnings, "还没有任何 pack（尚未备份）")
	}

	referencedCount, orphanCount, missingCount := 0, 0, 0
	if *checkChain && layout != nil {
		if pw, perr := a.password(g, "请输入主密码：", false); perr != nil {
			warnings = append(warnings, "未能取得主密码，packs.referenced/orphan/missing 未计算")
		} else {
			keys, kerr := s.meta.Unlock(pw)
			zero(pw)
			if kerr != nil {
				warnings = append(warnings, "主密码无法解锁 vault，链统计未计算")
			} else {
				s.keys = keys
				chain, cerr := journal.Load(layout, keys.Sub.Journal.Bytes(), keys.VaultID[:], journal.LoadOptions{})
				if cerr != nil {
					warnings = append(warnings, "链校验失败："+cerr.Error())
				} else {
					localSet := make(map[string]bool, len(packs))
					for _, name := range packs {
						localSet[name] = true
					}
					for name := range chain.Tree.Packs {
						referencedCount++
						if !localSet[name] {
							missingCount++
						}
					}
					orphanCount = len(packs) - (referencedCount - missingCount)
					if a, ok, _ := s.db.LatestAnchor(); ok {
						mac := vaultcrypto.AnchorMAC(keys.Sub.Anchor.Bytes(), a.Seq, a.JournalSHA)
						switch {
						case mac != a.MAC:
							verified = false
							warnings = append(warnings, "锚点 MAC 校验失败（state.db 可能被篡改）")
						case a.Seq < chain.LastSeq:
							warnings = append(warnings, fmt.Sprintf("锚点 seq=%d 落后于磁盘 %d", a.Seq, chain.LastSeq))
						}
					} else {
						warnings = append(warnings, "本地没有锚点（无法检测回滚）")
					}
				}
			}
		}
	}

	type packsJSON struct {
		Local      int `json:"local"`
		Referenced int `json:"referenced"`
		Orphan     int `json:"orphan"`
		Missing    int `json:"missing"`
	}
	type bytesJSON struct {
		PackTotal    int64 `json:"pack_total"`
		JournalTotal int64 `json:"journal_total"`
		Staging      int64 `json:"staging"`
		Logical      int64 `json:"logical_source"`
	}
	doc := struct {
		Schema      int       `json:"schema"`
		VaultID     string    `json:"vault_id"`
		LastSeq     uint64    `json:"last_seq"`
		AnchorShort string    `json:"anchor_short"`
		Verified    bool      `json:"verified"`
		Packs       packsJSON `json:"packs"`
		Bytes       bytesJSON `json:"bytes"`
		TmpEntries  int       `json:"tmp_entries"`
		Warnings    []string  `json:"warnings"`
	}{
		Schema:      1,
		VaultID:     s.meta.VaultID,
		LastSeq:     lastSeq,
		AnchorShort: anchorShort,
		Verified:    verified,
		Packs: packsJSON{
			Local: len(packs), Referenced: referencedCount,
			Orphan: orphanCount, Missing: missingCount,
		},
		Bytes:      bytesJSON{PackTotal: packBytes, JournalTotal: journalBytes, Staging: stagingBytes},
		TmpEntries: len(stagingEntries),
		Warnings:   warnings,
	}
	return s.printJSONOrHuman(doc, func() {
		w := s.stdout
		fmt.Fprintf(w, "Vault        %s\n", homeDirForDisplay(s.vaultDir))
		fmt.Fprintf(w, "vault_id     %s\n", s.meta.VaultID)
		fmt.Fprintf(w, "Last commit  seq %d\n", lastSeq)
		if hasAnchor {
			fmt.Fprintf(w, "Anchor       %s\n", anchorShort)
		} else {
			fmt.Fprintf(w, "Anchor       无（尚未提交过）\n")
		}
		if *checkChain {
			fmt.Fprintf(w, "Data         %s in %d packs（引用 %d · 孤儿 %d · 缺失 %d）\n",
				humanBytes(packBytes), len(packs), referencedCount, orphanCount, missingCount)
		} else {
			fmt.Fprintf(w, "Data         %s in %d packs\n", humanBytes(packBytes), len(packs))
		}
		fmt.Fprintf(w, "Journals     %s in %d files\n", humanBytes(journalBytes), len(journals))
		fmt.Fprintf(w, "Staging      %s in %d entries\n", humanBytes(stagingBytes), len(stagingEntries))
		fmt.Fprintf(w, "Health       %s\n", strings.Join(append([]string{anchorHealth(verified, hasAnchor)}, warnings...), " · "))
		fmt.Fprintln(s.stderr, "提示：主密码不可更改；请确认 Armor Key 已异地保存，并定期做恢复演练。")
	})
}

func anchorHealth(verified, hasAnchor bool) string {
	switch {
	case verified:
		return "anchor OK"
	case hasAnchor:
		return "anchor 落后于磁盘（state.db 可能滞后）"
	default:
		return "无锚点（无法检测回滚）"
	}
}

// newLayout builds the TargetDir layout from the config.
func newLayout(cfg *config.Config) (*store.Layout, error) {
	return store.NewLayout(cfg.Storage.TargetDir, cfg.Storage.StagingDir)
}
