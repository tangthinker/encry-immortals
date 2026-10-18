package cli

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/index"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
)

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func cmdDoctor(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	checkChain := fs.Bool("chain", false, "解密并校验整条哈希链（需要主密码）")
	camouflage := fs.Bool("camouflage", false, "检查 TargetDir 的伪装命名与文件头（06.7）")
	selfCheck := fs.Bool("self-check", false, "运行可运行时验证的不变量检查")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	s, err := a.openSession(g, false)
	if err != nil {
		return err
	}
	defer s.Close()

	var checks []checkResult
	add := func(name, status, detail string) {
		checks = append(checks, checkResult{Name: name, Status: status, Detail: detail})
	}
	add("vault.meta", "PASS", "已加载，版本 "+fmt.Sprint(s.meta.Version))

	if isSyncDirectory(s.vaultDir) {
		add("控制平面位置", "FAIL", "控制平面位于同步目录内："+homeDirForDisplay(s.vaultDir))
	} else {
		add("控制平面位置", "PASS", homeDirForDisplay(s.vaultDir))
	}

	var layout *store.Layout
	if strings.TrimSpace(s.cfg.Storage.TargetDir) != "" {
		l, lerr := newLayout(s.cfg)
		if lerr != nil {
			add("TargetDir", "FAIL", lerr.Error())
		} else {
			layout = l
			if verr := layout.ValidateTopLevel(); verr != nil {
				add("TargetDir 白名单", "FAIL", verr.Error())
			} else {
				add("TargetDir 白名单", "PASS", "只包含 .tmp/、.eimmortal.lock、data/、meta/（忽略 .DS_Store）")
			}
			if verr := layout.ValidateStagingVolume(); verr != nil {
				add("暂存区同卷", "FAIL", verr.Error())
			} else {
				add("暂存区同卷", "PASS", homeDirForDisplay(layout.StagingDir))
			}
			if entries, rerr := os.ReadDir(layout.StagingDir); rerr == nil {
				if len(entries) == 0 {
					add("暂存区残留", "PASS", "0 个条目")
				} else {
					add("暂存区残留", "WARN", fmt.Sprintf("%d 个条目（云端可能看到残片）", len(entries)))
				}
			}
			seqs, serr := layout.ListJournals()
			if serr != nil {
				add("journal 序号", "FAIL", serr.Error())
			} else if gap := firstGap(seqs); gap != 0 {
				add("journal 序号", "FAIL", fmt.Sprintf("缺少 seq=%d", gap))
			} else {
				add("journal 序号", "PASS", fmt.Sprintf("连续 1..%d", lastOf(seqs)))
			}
		}
	} else {
		add("TargetDir", "SKIP", "未配置")
	}

	if *camouflage && layout != nil {
		runCamouflageChecks(layout, add)
	}

	if *checkChain || *selfCheck {
		if layout == nil {
			add("哈希链", "SKIP", "未配置 TargetDir")
		} else {
			pw, perr := a.password(g, "请输入主密码：", false)
			if perr != nil {
				add("哈希链", "SKIP", "无法取得主密码："+perr.Error())
			} else {
				keys, kerr := s.meta.Unlock(pw)
				zero(pw)
				if kerr != nil {
					add("哈希链", "FAIL", "无法解锁 vault.meta")
				} else {
					s.keys = keys
					chain, cerr := journal.Load(layout, keys.Sub.Journal.Bytes(), keys.VaultID[:], journal.LoadOptions{})
					if cerr != nil {
						add("哈希链", "FAIL", cerr.Error())
					} else {
						add("哈希链", "PASS", fmt.Sprintf("已验证 %d 个 journal，最新 seq=%d", len(chain.Files), chain.LastSeq))
						anchor, ok, aerr := s.db.LatestAnchor()
						switch {
						case aerr != nil:
							add("本地锚点", "FAIL", aerr.Error())
						case !ok:
							add("本地锚点", "WARN", "没有锚点（无法检测回滚）")
						default:
							mac := vaultcrypto.AnchorMAC(keys.Sub.Anchor.Bytes(), anchor.Seq, anchor.JournalSHA)
							if mac != anchor.MAC {
								add("本地锚点", "FAIL", "锚点 MAC 校验失败（state.db 可能被篡改）")
							} else if anchor.Seq > chain.LastSeq {
								add("本地锚点", "FAIL", fmt.Sprintf("疑似回滚：锚点 seq=%d，磁盘只有 %d", anchor.Seq, chain.LastSeq))
							} else if anchor.Seq < chain.LastSeq {
								add("本地锚点", "WARN", fmt.Sprintf("锚点 seq=%d 落后于磁盘 %d（state.db 可能滞后）", anchor.Seq, chain.LastSeq))
							} else {
								add("本地锚点", "PASS", "与磁盘一致 "+shortAnchor(anchor.MAC))
							}
						}
						local, lerr := layout.ListPacks()
						if lerr == nil {
							orphans := 0
							for _, name := range local {
								if _, ok := chain.Tree.Packs[name]; !ok {
									orphans++
								}
							}
							if orphans == 0 {
								add("孤儿 pack", "PASS", "0 个")
							} else {
								add("孤儿 pack", "WARN", fmt.Sprintf("%d 个（eimmortal gc 可查看）", orphans))
							}
						}
					}
				}
			}
		}
	}

	failed := false
	for _, c := range checks {
		if c.Status == "FAIL" {
			failed = true
		}
	}
	if err := s.printJSONOrHuman(checks, func() {
		for _, c := range checks {
			fmt.Fprintf(s.stdout, "%-4s %-14s %s\n", c.Status, c.Name, c.Detail)
		}
	}); err != nil {
		return err
	}
	if failed {
		return apexerr.New(apexerr.CodeCorrupt, "doctor 检出至少一项 FAIL").
			WithNext("按上面的条目逐项处理；--chain 可复现链校验")
	}
	return nil
}

func isSyncDirectory(p string) bool {
	markers := []string{"/Dropbox/", "/OneDrive", "/Google Drive", "/iCloud", "Mobile Documents", "/pCloudDrive/", "/pCloud/"}
	p = filepath.ToSlash(p) + "/"
	for _, m := range markers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

func firstGap(seqs []uint64) uint64 {
	for i, s := range seqs {
		if s != uint64(i+1) {
			return uint64(i + 1)
		}
	}
	return 0
}

func lastOf(seqs []uint64) uint64 {
	if len(seqs) == 0 {
		return 0
	}
	return seqs[len(seqs)-1]
}

func cmdVerify(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	_ = fs.Bool("size", true, "校验 pack 大小与 journal 记录一致（默认开启，始终执行）")
	sample := fs.Int("sample", 0, "随机抽样 N 个 pack 做整包 SHA-256 校验")
	deep := fs.Bool("deep", false, "全量解密并逐切片校验（最慢，等价于不落盘的 restore）")
	at := fs.Uint64("at", 0, "只校验到指定 seq")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
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
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:],
		journal.LoadOptions{TargetSeq: *at})
	if err != nil {
		return err
	}
	local, err := layout.ListPacks()
	if err != nil {
		return err
	}
	localSet := make(map[string]bool, len(local))
	for _, name := range local {
		localSet[name] = true
	}
	var referenced []string
	for name := range chain.Tree.Packs {
		referenced = append(referenced, name)
	}
	sort.Strings(referenced)
	var missing, sizeMismatch, orphans []string
	for _, name := range referenced {
		if !localSet[name] {
			missing = append(missing, name)
			continue
		}
		abs, aerr := layout.AbsPath(name)
		if aerr != nil {
			continue
		}
		info, serr := os.Stat(abs)
		if serr != nil {
			missing = append(missing, name)
			continue
		}
		if uint64(info.Size()) != chain.Tree.Packs[name].Size {
			sizeMismatch = append(sizeMismatch, fmt.Sprintf("%s（%d != %d）", name, info.Size(), chain.Tree.Packs[name].Size))
		}
	}
	for _, name := range local {
		if _, ok := chain.Tree.Packs[name]; !ok {
			orphans = append(orphans, name)
		}
	}
	reader, err := store.NewPackReader(layout, s.keys.Sub.Storage.Bytes())
	if err != nil {
		return err
	}
	defer reader.Close()

	var sampled []string
	if *sample > 0 {
		step := len(referenced) / *sample
		if step < 1 {
			step = 1
		}
		for i := 0; i < len(referenced) && len(sampled) < *sample; i += step {
			sampled = append(sampled, referenced[i])
		}
	}
	var sampleFailures []string
	for _, name := range sampled {
		if !localSet[name] {
			continue
		}
		if verr := reader.VerifyPack(chain.Tree.Packs[name]); verr != nil {
			sampleFailures = append(sampleFailures, name+": "+verr.Error())
		}
	}
	var deepFailures []string
	var deepFiles int
	var deepBytes uint64
	if *deep {
		for _, n := range chain.Tree.Files() {
			deepFiles++
			for i, ref := range n.Slices {
				packName := n.PackNames[i]
				if !localSet[packName] {
					continue
				}
				h, oerr := reader.Open(packName, chain.Tree.Packs[packName].Size)
				if oerr != nil {
					deepFailures = append(deepFailures, n.Path+": "+oerr.Error())
					break
				}
				plain, rerr := reader.ReadSlice(h, ref, n.TxnID)
				if rerr != nil {
					deepFailures = append(deepFailures, n.Path+": "+rerr.Error())
					break
				}
				deepBytes += uint64(len(plain))
			}
		}
	}

	type verifyJSON struct {
		Local      int      `json:"local_packs"`
		Referenced int      `json:"referenced_packs"`
		Missing    []string `json:"missing"`
		SizeBad    []string `json:"size_mismatch"`
		Orphans    int      `json:"orphans"`
		Sampled    int      `json:"sampled"`
		SampleBad  []string `json:"sample_failures"`
		DeepFiles  int      `json:"deep_files"`
		DeepBytes  uint64   `json:"deep_bytes"`
		DeepBad    []string `json:"deep_failures"`
	}
	doc := verifyJSON{
		Local: len(local), Referenced: len(referenced), Missing: missing, SizeBad: sizeMismatch,
		Orphans: len(orphans), Sampled: len(sampled), SampleBad: sampleFailures,
		DeepFiles: deepFiles, DeepBytes: deepBytes, DeepBad: deepFailures,
	}
	if err := s.printJSONOrHuman(doc, func() {
		fmt.Fprintf(s.stdout, "本地 pack %d · journal 引用 %d · 缺失 %d · 大小不符 %d · 孤儿 %d\n",
			doc.Local, doc.Referenced, len(doc.Missing), len(doc.SizeBad), doc.Orphans)
		if len(sampled) > 0 {
			fmt.Fprintf(s.stdout, "抽样校验 %d 个 pack，失败 %d 个\n", len(sampled), len(sampleFailures))
		}
		if *deep {
			fmt.Fprintf(s.stdout, "深度校验 %d 个文件 / %s，失败 %d 个\n", deepFiles, humanBytes(int64(deepBytes)), len(deepFailures))
		}
		for _, m := range doc.Missing {
			fmt.Fprintf(s.stdout, "  缺失：%s\n", m)
		}
		for _, m := range doc.SizeBad {
			fmt.Fprintf(s.stdout, "  大小不符：%s\n", m)
		}
		for _, m := range doc.SampleBad {
			fmt.Fprintf(s.stdout, "  抽样失败：%s\n", m)
		}
		for _, m := range doc.DeepBad {
			fmt.Fprintf(s.stdout, "  深度失败：%s\n", m)
		}
	}); err != nil {
		return err
	}
	switch {
	case len(missing) > 0:
		return apexerr.Newf(apexerr.CodeIncomplete, "有 %d 个被引用的 pack 缺失", len(missing)).
			WithScope("可能尚未从云端同步完成").
			WithNext("等待同步后重试；必要时使用 restore --wait-for-packs")
	case len(sizeMismatch) > 0:
		return apexerr.Newf(apexerr.CodeCorrupt, "有 %d 个 pack 大小与 journal 记录不符", len(sizeMismatch))
	case len(sampleFailures) > 0 || len(deepFailures) > 0:
		return apexerr.New(apexerr.CodeCorrupt, "完整性校验失败").
			WithNext("用 eimmortal verify --deep 定位损坏范围；必要时从其他副本恢复该 pack")
	}
	return nil
}

func cmdGC(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	prune := fs.Bool("prune-orphans", false, "删除从未被任何 journal 引用的本地 pack")
	yes := fs.Bool("yes", false, "确认破坏性操作")
	dryRun := fs.Bool("dry-run", false, "只报告不删除")
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
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
	removed, freed, err := store.SweepStaging(layout.StagingDir, nowUnix(), 24*3600)
	if err != nil {
		return err
	}
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		return err
	}
	local, err := layout.ListPacks()
	if err != nil {
		return err
	}
	var orphans []string
	var orphanBytes int64
	for _, name := range local {
		if _, ok := chain.Tree.Packs[name]; ok {
			continue
		}
		orphans = append(orphans, name)
		if abs, aerr := layout.AbsPath(name); aerr == nil {
			if info, serr := os.Stat(abs); serr == nil {
				orphanBytes += info.Size()
			}
		}
	}
	manifests, err := layout.ListManifests()
	if err != nil {
		return err
	}
	localBases := make(map[string]bool, len(local))
	for _, name := range local {
		localBases[strings.TrimSuffix(filepath.Base(name), store.PackSuffix)] = true
	}
	var orphanManifests []string
	for _, name := range manifests {
		if !localBases[strings.TrimSuffix(name, store.ManifestSuffix)] {
			orphanManifests = append(orphanManifests, name)
		}
	}
	var pruned, prunedManifests int
	if *prune {
		if !*yes {
			return apexerr.New(apexerr.CodeUsage, "gc --prune-orphans 需要 --yes 二次确认").
				WithScope("孤儿 pack 可能是尚未提交成功但仍有价值的数据").
				WithNext("确认后执行 eimmortal gc --prune-orphans --yes")
		}
		if !*dryRun {
			for _, name := range orphans {
				abs, aerr := layout.AbsPath(name)
				if aerr != nil {
					continue
				}
				if rerr := os.Remove(abs); rerr == nil {
					pruned++
				}
				if mrel := layout.ManifestRelPath(name); mrel != "" {
					if mabs, merr := layout.AbsPath(mrel); merr == nil {
						if rerr := os.Remove(mabs); rerr == nil {
							prunedManifests++
						}
					}
				}
			}
			for _, name := range orphanManifests {
				if rerr := os.Remove(filepath.Join(layout.ManifestDir, name)); rerr == nil {
					prunedManifests++
				}
			}
		}
	}
	type gcJSON struct {
		StagingRemoved  int      `json:"staging_removed"`
		StagingFreed    int64    `json:"staging_freed"`
		Orphans         []string `json:"orphans"`
		OrphanBytes     int64    `json:"orphan_bytes"`
		OrphanManifests []string `json:"orphan_manifests"`
		Pruned          int      `json:"pruned"`
		PrunedManifests int      `json:"pruned_manifests"`
	}
	doc := gcJSON{
		StagingRemoved: removed, StagingFreed: freed, Orphans: orphans, OrphanBytes: orphanBytes,
		OrphanManifests: orphanManifests, Pruned: pruned, PrunedManifests: prunedManifests,
	}
	return s.printJSONOrHuman(doc, func() {
		fmt.Fprintf(s.stdout, "暂存区：清理 %d 个超过 24h 的残留（%s）\n", removed, humanBytes(freed))
		fmt.Fprintf(s.stdout, "孤儿 pack：%d 个（%s）\n", len(orphans), humanBytes(orphanBytes))
		for _, name := range orphans {
			fmt.Fprintf(s.stdout, "  %s\n", name)
		}
		if len(orphanManifests) > 0 {
			fmt.Fprintf(s.stdout, "孤儿 manifest：%d 个\n", len(orphanManifests))
			for _, name := range orphanManifests {
				fmt.Fprintf(s.stdout, "  %s\n", name)
			}
		}
		if pruned > 0 {
			fmt.Fprintf(s.stdout, "已删除 %d 个孤儿 pack（仅本地）\n", pruned)
		}
		if prunedManifests > 0 {
			fmt.Fprintf(s.stdout, "已删除 %d 个孤儿 manifest\n", prunedManifests)
		}
		fmt.Fprintln(s.stderr, "提示：程序不会删除云端文件；如需清理请自行在网盘客户端操作。")
	})
}

func cmdRebuildState(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("rebuild-state", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
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
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		return err
	}
	if err := s.db.Reset(); err != nil {
		return err
	}
	if err := s.db.SetVaultID(s.keys.VaultID[:]); err != nil {
		return err
	}
	pathKey := s.keys.Sub.Path.Bytes()
	entries, dirs := 0, 0
	for _, n := range chain.Tree.Files() {
		hm := vaultcrypto.PathHMAC(pathKey, []byte(n.Path))
		if err := s.db.PutEntry(index.Entry{
			PathHMAC: hm, Size: int64(n.Size), MtimeNS: n.ModTimeNS,
			ContentSHA256: n.ContentSHA256, LastSeq: chain.LastSeq,
		}); err != nil {
			return err
		}
		entries++
	}
	for _, n := range chain.Tree.Dirs() {
		hm := vaultcrypto.PathHMAC(pathKey, []byte(n.Path))
		if err := s.db.PutDir(index.Dir{PathHMAC: hm, Mode: n.Mode, LastSeq: chain.LastSeq}); err != nil {
			return err
		}
		dirs++
	}
	if err := s.db.SetLastSeq(chain.LastSeq); err != nil {
		return err
	}
	if chain.LastSeq > 0 {
		mac := vaultcrypto.AnchorMAC(s.keys.Sub.Anchor.Bytes(), chain.LastSeq, chain.LastSHA)
		if err := s.db.PutAnchor(chain.LastSeq, chain.LastSHA, mac); err != nil {
			return err
		}
	}
	fmt.Fprintf(s.stdout, "state.db 已重建：entries=%d dirs=%d last_seq=%d\n", entries, dirs, chain.LastSeq)
	return nil
}

var _ = sha256.Sum256

// runCamouflageChecks implements the audit list of spec 06.7.
func runCamouflageChecks(layout *store.Layout, add func(name, status, detail string)) {
	packRe := regexp.MustCompile(`^pack_[0-9]{13}_[0-9a-z]{6}\.dat$`)
	forbidden := []string{".enc", ".crypto", ".zip", ".bak", ".docx", ".mp4", ".pdf", ".tar", ".gz"}
	var badExt []string
	var badNames []string
	magicHit := ""
	checked := 0
	err := filepath.WalkDir(layout.TargetDir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		lower := strings.ToLower(name)
		for _, ext := range forbidden {
			if strings.HasSuffix(lower, ext) {
				badExt = append(badExt, name)
			}
		}
		rel, _ := filepath.Rel(layout.TargetDir, p)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, store.DataDirName+"/") && strings.HasSuffix(name, store.PackSuffix) {
			if !packRe.MatchString(name) {
				badNames = append(badNames, rel)
				return nil
			}
			if checked < 8 && magicHit == "" {
				checked++
				f, oerr := os.Open(p)
				if oerr == nil {
					head := make([]byte, 16)
					if n, _ := f.Read(head); n >= 8 {
						for _, sig := range [][]byte{{0x50, 0x4b, 0x03, 0x04}, []byte("%PDF"), {0x89, 0x50, 0x4e, 0x47}, {0x1f, 0x8b}} {
							if bytes.HasPrefix(head[:n], sig) {
								magicHit = rel
							}
						}
					}
					f.Close()
				}
			}
		}
		return nil
	})
	if err != nil {
		add("伪装检查", "FAIL", "无法遍历 TargetDir："+err.Error())
		return
	}
	if len(badExt) > 0 {
		add("伪装扩展名", "FAIL", "出现可疑扩展名："+strings.Join(firstFew(badExt, 5), ", "))
	} else {
		add("伪装扩展名", "PASS", "只有 .dat / .journal / .manifest")
	}
	if len(badNames) > 0 {
		add("pack 命名", "FAIL", "不符合 pack_<13位>_<6位36进制>.dat："+strings.Join(firstFew(badNames, 3), ", "))
	} else {
		add("pack 命名", "PASS", "全部符合 pack_<13位>_<6位36进制>.dat")
	}
	if magicHit != "" {
		add("文件头魔数", "FAIL", "检测到已知文件类型魔数："+magicHit)
	} else {
		add("文件头魔数", "PASS", "抽查的 pack 头没有可识别魔数")
	}
}

func firstFew(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(append([]string{}, items[:n]...), "…")
}
