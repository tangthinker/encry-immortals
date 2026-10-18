package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/pipeline"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func cmdManifest(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	if err := fs.Parse(args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	arg := fs.Arg(0)
	if arg == "" {
		return apexerr.New(apexerr.CodeUsage, "用法：eimmortal manifest <pack 路径或文件名>")
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
	packName, err := resolvePackName(layout, arg)
	if err != nil {
		return err
	}
	doc, err := pipeline.ReadManifest(layout, s.keys, packName)
	if err != nil {
		return err
	}
	return s.printJSONOrHuman(doc, func() {
		fmt.Fprintf(s.stdout, "pack   %s\n", doc.Pack)
		fmt.Fprintf(s.stdout, "大小   %s · seq %d · tx %x\n",
			humanBytes(int64(doc.PackSize)), doc.Seq, doc.TxnID)
		fmt.Fprintf(s.stdout, "文件   %d 个\n", len(doc.Ops))
		for _, op := range doc.Ops {
			extra := ""
			if len(op.Packs) > 1 {
				extra = fmt.Sprintf("  (跨 %d 个 pack，%d 个切片)", len(op.Packs), len(op.Slices))
			}
			fmt.Fprintf(s.stdout, "  %-6s %-10s %s%s\n",
				wire.OpType(op.Type), humanBytes(int64(op.Size)), op.Path, extra)
		}
	})
}

// resolvePackName accepts a TargetDir-relative pack path, a pack file name, or
// a pack base name without the .dat suffix.
func resolvePackName(layout *store.Layout, arg string) (string, error) {
	if strings.Contains(arg, "/") {
		if _, err := layout.AbsPath(arg); err != nil {
			return "", err
		}
		return filepath.ToSlash(arg), nil
	}
	packs, err := layout.ListPacks()
	if err != nil {
		return "", err
	}
	var matches []string
	for _, name := range packs {
		base := filepath.Base(name)
		if base == arg || strings.TrimSuffix(base, store.PackSuffix) == arg {
			matches = append(matches, name)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", apexerr.Newf(apexerr.CodeUsage, "找不到 pack：%s", arg).
			WithNext("查看 TargetDir 下 data/ 里的 pack 文件名")
	default:
		return "", apexerr.Newf(apexerr.CodeUsage, "%s 匹配到多个 pack，请写完整路径", arg)
	}
}
