package cli

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/config"
)

func registerAll() {
	register(&command{name: "init", summary: "初始化新 vault，或 --join <TargetDir> 加入已有库", run: cmdInit})
	register(&command{name: "backup", summary: "执行一次增量备份（--source 必填）", writesTarget: true, run: cmdBackup})
	register(&command{name: "restore", summary: "还原到目标目录（可 --at <seq>）", run: cmdRestore})
	register(&command{name: "log", summary: "列出提交历史", run: cmdLog})
	register(&command{name: "show", summary: "查看某次提交的变更明细", run: cmdShow})
	register(&command{name: "ls", summary: "以某快照视角列出文件树", run: cmdLs})
	register(&command{name: "cat", summary: "输出某文件在某快照下的内容", run: cmdCat})
	register(&command{name: "verify", summary: "校验完整性：--size（默认）/ --sample N / --deep", run: cmdVerify})
	register(&command{name: "status", summary: "水位、锚点、容量与健康度", run: cmdStatus})
	register(&command{name: "doctor", summary: "一致性自检；--chain 校验哈希链与孤儿", run: cmdDoctor})
	register(&command{name: "export-key", summary: "输出 Armor Key（单行 + 分组两种形式）", run: cmdExportKey})
	register(&command{name: "import-key", summary: "导入 Armor Key（stdin 或 --key-file）", run: cmdImportKey})
	register(&command{name: "gc", summary: "清理 .tmp/ 残留、报告孤儿 pack（--prune-orphans --yes 删除）", writesTarget: true, run: cmdGC})
	register(&command{name: "rebuild-state", summary: "从 journal 全量重建 state.db", run: cmdRebuildState})
	register(&command{name: "note", summary: "写一条纯注释 journal（不含 ops）", writesTarget: true, run: cmdNote})
	register(&command{name: "compact", summary: "重建一个只含当前快照的新库（--out，可 --new-identity）", writesTarget: true, run: cmdCompact})
	register(&command{name: "version", summary: "打印版本号", run: cmdVersion})
}

// humanBytes renders a byte count for humans.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	value := float64(n)
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f EiB", value/unit)
}

// shortAnchor renders the 8-character water-level code from the anchor MAC.
func shortAnchor(mac [32]byte) string {
	s := strings.ToUpper(hex.EncodeToString(mac[:4]))
	return s[:4] + "-" + s[4:]
}

// requireTarget makes sure a TargetDir is configured.
func requireTarget(cfg *config.Config) error {
	if strings.TrimSpace(cfg.Storage.TargetDir) == "" {
		return apexerr.New(apexerr.CodeUsage, "未配置 TargetDir").
			WithNext("在 config.toml 的 [storage] 段设置 target_dir")
	}
	return nil
}

// parseUintFlag parses a decimal sequence number.
func parseUintFlag(s, what string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, apexerr.Newf(apexerr.CodeUsage, "%s 不是合法的序号：%q", what, s)
	}
	return v, nil
}

// modeString renders a POSIX mode.
func modeString(mode uint32) string {
	return fmt.Sprintf("%04o", mode&0o7777)
}

// homeDirForDisplay shortens the home prefix in human output.
func homeDirForDisplay(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// nowUnix is the single clock entry point for CLI-driven sweeps.
func nowUnix() int64 { return time.Now().Unix() }

// parseInterspersed parses flags that may appear before, after or between
// positional arguments (spec 10.1 writes "restore <DestDir> --at <seq>").
// The standard flag package stops at the first positional, so we reorder.
func parseInterspersed(fs *flag.FlagSet, args []string) error {
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' || a == "--" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			continue // value is inline
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // unknown flag: let Parse report it
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return fs.Parse(append(flags, positional...))
}
