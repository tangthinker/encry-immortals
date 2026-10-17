// Package scan walks the source directory and rejects everything eimmortal cannot
// back up losslessly (spec 01.6 D-18, 09.6).
package scan

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/pathx"
)

// Kind classifies a scanned entry.
type Kind uint8

// Entry kinds.
const (
	KindFile Kind = iota
	KindDir
	KindSymlink
)

// Entry is one scanned source entry.
type Entry struct {
	Path       string // NFC-normalised, '/'-separated, relative to the root
	Kind       Kind
	Mode       uint32
	Size       int64
	ModTimeNS  int64
	CtimeNS    int64
	Ino        uint64
	Dev        uint64
	Nlink      uint64
	Sparse     bool
	LinkTarget string
}

// Options configures a scan.
type Options struct {
	Root                 string
	Excludes             []string
	FollowHardlinks      bool // "split": explicitly accept the degradation
	SparseMaxBytes       int64
	IgnoreXattr          bool // "ignore_xattr": explicitly accept xattr/ACL loss
	AllowExternalSymlink bool
}

// Result is the complete scan output.
type Result struct {
	Root          string
	RootMode      uint32
	RootModTimeNS int64
	Entries       []Entry
}

// Scan walks Root and returns every supported entry, sorted by path.
func Scan(opts Options) (*Result, error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "源目录路径非法：%s", opts.Root)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法访问源目录：%s", root)
	}
	if !info.IsDir() {
		return nil, apexerr.Newf(apexerr.CodeUsage, "源目录不是目录：%s", root)
	}
	res := &Result{Root: root, RootMode: uint32(info.Mode().Perm()) | specialBits(info.Mode()), RootModTimeNS: info.ModTime().UnixNano()}

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return apexerr.Wrapf(walkErr, apexerr.CodeUnsupported, "扫描失败：%s", p)
		}
		if p == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if Excluded(opts.Excludes, rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		normalized, normErr := pathx.Normalize(rel)
		if normErr != nil {
			return apexerr.Newf(apexerr.CodeUnsupported, "无法处理的路径：%s", rel).WithErr(normErr)
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return apexerr.Wrapf(ierr, apexerr.CodeUnsupported, "无法读取元数据：%s", rel)
		}
		mode := fi.Mode()
		e := Entry{
			Path:      normalized,
			Mode:      uint32(mode.Perm()) | specialBits(mode),
			Size:      fi.Size(),
			ModTimeNS: fi.ModTime().UnixNano(),
			CtimeNS:   ctimeNS(fi),
		}
		if ino, dev, nlink, blocks, ok := sysInfo(fi); ok {
			e.Ino, e.Dev, e.Nlink = ino, dev, nlink
			if mode.IsRegular() && fi.Size() > 0 && blocks*512 < fi.Size() {
				e.Sparse = true
			}
		}
		if !opts.IgnoreXattr {
			has, names, xerr := hasXattrs(p)
			if xerr != nil {
				return apexerr.Wrapf(xerr, apexerr.CodeUnsupported, "无法读取扩展属性：%s", normalized)
			}
			if has {
				return apexerr.Newf(apexerr.CodeUnsupported,
					"检测到扩展属性（xattr）：%s（%d 个：%s）", normalized, len(names), strings.Join(firstNames(names, 3), ", ")).
					WithScope("xattr / ACL 无法在还原时保留，属于会静默丢失的元数据").
					WithNext("在 config.toml 设置 scan.ignore_xattr = true 显式接受降级，或用 scan.exclude 排除该路径")
			}
		}
		switch {
		case mode.IsDir():
			e.Kind = KindDir
		case mode.IsRegular():
			e.Kind = KindFile
			if e.Nlink > 1 && !opts.FollowHardlinks {
				return apexerr.Newf(apexerr.CodeUnsupported, "检测到硬链接：%s", normalized).
					WithScope("还原后会变成两份独立文件，语义丢失").
					WithNext("把 --follow-hardlinks=split 加入配置以显式接受降级，或用 --exclude 排除")
			}
			if e.Sparse && fi.Size() > opts.SparseMaxBytes {
				return apexerr.Newf(apexerr.CodeUnsupported, "检测到稀疏文件：%s（%d 字节）", normalized, e.Size).
					WithScope("按逻辑大小读取会膨胀为全量大小").
					WithNext("调大 scan.sparse_max_bytes，或排除该文件")
			}
		case mode&os.ModeSymlink != 0:
			e.Kind = KindSymlink
			target, rerr := os.Readlink(p)
			if rerr != nil {
				return apexerr.Wrapf(rerr, apexerr.CodeUnsupported, "无法读取符号链接：%s", normalized)
			}
			e.LinkTarget = target
			if !opts.AllowExternalSymlink {
				resolved := target
				if !filepath.IsAbs(target) {
					resolved = filepath.Join(filepath.Dir(p), target)
				}
				inside, cerr := pathx.Contains(root, resolved)
				if cerr != nil {
					return apexerr.Wrapf(cerr, apexerr.CodeUnsupported, "无法解析符号链接：%s", normalized)
				}
				if !inside {
					err := apexerr.Newf(apexerr.CodeUnsupported, "符号链接指向源目录之外：%s -> %s", normalized, target).
						WithScope("还原时可能写入源目录之外的位置").
						WithNext("用 --exclude 排除该链接，或在配置里显式允许外部链接")
					return err
				}
			}
		default:
			return apexerr.Newf(apexerr.CodeUnsupported, "不支持的文件类型：%s（%s）", normalized, mode.String()).
				WithScope("设备文件、FIFO、socket 无法无损备份").
				WithNext("用 scan.exclude 排除该路径")
		}
		res.Entries = append(res.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if a, b, ok := pathx.CaseFoldConflicts(pathsOf(res.Entries)); ok {
		return nil, apexerr.Newf(apexerr.CodeUnsupported,
			"大小写折叠冲突：%q 与 %q", a, b).
			WithScope("在大小写不敏感的文件系统上会互相覆盖").
			WithNext("重命名其中一个后重试")
	}
	return res, nil
}

// firstNames returns at most n names for an error message.
func firstNames(names []string, n int) []string {
	if len(names) <= n {
		return names
	}
	return append(append([]string{}, names[:n]...), "…")
}

func pathsOf(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

// Excluded applies the scan.exclude globs.
//
// Supported forms: "dir/**" (prefix), "a/b.txt" (exact path or glob with '/'),
// "*.tmp" (basename at any depth).
func Excluded(patterns []string, rel string) bool {
	for _, p := range patterns {
		if matchOne(p, rel) {
			return true
		}
	}
	return false
}

func matchOne(pattern, rel string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return rel == prefix || strings.HasPrefix(rel, prefix+"/")
	}
	if strings.Contains(pattern, "/") {
		ok, err := path.Match(pattern, rel)
		return err == nil && ok
	}
	ok, err := path.Match(pattern, path.Base(rel))
	return err == nil && ok
}

func specialBits(m os.FileMode) uint32 {
	var out uint32
	if m&os.ModeSetuid != 0 {
		out |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		out |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		out |= 0o1000
	}
	return out
}

// ctimeNS returns the inode change time when the platform exposes it.
func ctimeNS(fi os.FileInfo) int64 { return ctime(fi) }

// SysInfo exposes the platform inode facts for callers outside this package
// (read-time consistency checks in the backup pipeline).
func SysInfo(fi os.FileInfo) (ino, dev, nlink uint64, blocks int64, ok bool) {
	return sysInfo(fi)
}

// CtimeNS exposes the inode change time for the same reason.
func CtimeNS(fi os.FileInfo) int64 { return ctime(fi) }

var _ = time.Now
