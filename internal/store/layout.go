// Package store owns the TargetDir layout, atomic publication and pack I/O
// (spec 01.1, 03, 05.1). It never derives keys and never touches the control
// plane; higher layers pass key material in.
package store

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// Directory and file names fixed by spec §01.1 / §03.1.
const (
	DataDirName    = "data"
	MetaDirName    = "meta"
	StagingDirName = ".tmp"
	LockFileName   = ".eimmortal.lock"
	// LegacyLockFileName is accepted in the whitelist so that vaults written by
	// older builds are not reported as polluted.
	LegacyLockFileName = ".apex.lock"
	// FinderMetadataFileName is created by macOS Finder when the directory is
	// browsed. It carries no vault content, so it is ignored rather than
	// treated as TargetDir pollution.
	FinderMetadataFileName = ".DS_Store"
	JournalSuffix          = ".journal"
	PackSuffix             = ".dat"
	// ManifestDirName holds one encrypted manifest per pack (a small per-pack
	// index used for progressive restore). It lives under meta/ so the top-level
	// whitelist does not change.
	ManifestDirName = "manifests"
	ManifestSuffix  = ".manifest"
	packPrefix      = "pack_"
	// JournalNameWidth is the zero-padded width of journal file names (§03.1).
	JournalNameWidth = 8
	// MaxSeq is the largest sequence representable by an 8-digit file name.
	MaxSeq = 99_999_999
)

// Layout describes one TargetDir on disk.
type Layout struct {
	TargetDir   string
	DataDir     string
	MetaDir     string
	ManifestDir string
	StagingDir  string
	// StagingExternal is true when staging was configured outside TargetDir
	// (spec §01.2), in which case a same-volume check is mandatory.
	StagingExternal bool
}

// NewLayout resolves target and staging directories to absolute paths.
func NewLayout(targetDir, stagingOverride string) (*Layout, error) {
	target, err := expandPath(targetDir)
	if err != nil {
		return nil, err
	}
	if target == "" {
		return nil, apexerr.New(apexerr.CodeUsage, "未配置 TargetDir").
			WithNext("在 config.toml 的 [storage] 段设置 target_dir")
	}
	l := &Layout{
		TargetDir:   target,
		DataDir:     filepath.Join(target, DataDirName),
		MetaDir:     filepath.Join(target, MetaDirName),
		ManifestDir: filepath.Join(target, MetaDirName, ManifestDirName),
		StagingDir:  filepath.Join(target, StagingDirName),
	}
	if strings.TrimSpace(stagingOverride) != "" {
		staging, err := expandPath(stagingOverride)
		if err != nil {
			return nil, err
		}
		l.StagingDir = staging
		l.StagingExternal = !samePath(staging, filepath.Join(target, StagingDirName))
	}
	return l, nil
}

func expandPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", apexerr.Wrap(err, apexerr.CodeUsage, "无法解析家目录")
		}
		p = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", apexerr.Wrap(err, apexerr.CodeUsage, fmt.Sprintf("路径非法：%s", p))
	}
	return abs, nil
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// Ensure creates the directories eimmortal owns.
func (l *Layout) Ensure() error {
	for _, dir := range []string{l.TargetDir, l.DataDir, l.MetaDir, l.ManifestDir, l.StagingDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建目录 %s", dir)
		}
	}
	return nil
}

// topLevelAllowed is the whitelist from spec §01.1 / I12.
var topLevelAllowed = map[string]bool{
	StagingDirName:     true,
	LockFileName:       true,
	LegacyLockFileName: true,
	DataDirName:        true,
	MetaDirName:        true,
}

// ValidateTopLevel enforces the TargetDir entry whitelist. Any foreign entry is
// pollution and must stop backup/restore (spec §01.1).
func (l *Layout) ValidateTopLevel() error {
	entries, err := os.ReadDir(l.TargetDir)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeUsage, "无法读取 TargetDir：%s", l.TargetDir)
	}
	for _, e := range entries {
		if e.Name() == FinderMetadataFileName && e.Type().IsRegular() {
			// macOS recreates this file without user action; it holds no vault
			// data, so it must not block backups. Anything else under that name
			// (e.g. a directory) is still pollution.
			continue
		}
		if !topLevelAllowed[e.Name()] {
			return apexerr.Newf(apexerr.CodeCorrupt, "TargetDir 内出现非白名单条目：%s", e.Name()).
				WithScope("该目录必须是网盘盲盒，只允许 .tmp/、.eimmortal.lock、data/、meta/（.DS_Store 会被忽略）").
				WithNext("把该条目移出 TargetDir 后重试")
		}
	}
	return nil
}

// ValidateStagingVolume enforces the same-filesystem requirement (§01.2).
func (l *Layout) ValidateStagingVolume() error {
	if !l.StagingExternal {
		return nil
	}
	same, err := sameVolume(l.StagingDir, l.DataDir)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeUsage, "无法校验暂存区与 Target 是否同卷")
	}
	if !same {
		return apexerr.New(apexerr.CodeUsage, "storage.staging_dir 与 TargetDir 不在同一个文件系统").
			WithScope("跨卷 rename 会退化为 copy+delete，产生半截文件的非原子窗口").
			WithNext("把 staging_dir 指回 TargetDir 内的 .tmp/，或指向同一卷的其他目录")
	}
	return nil
}

// AbsPath resolves a TargetDir-relative path containing '/'.
func (l *Layout) AbsPath(rel string) (string, error) {
	rel = filepath.FromSlash(rel)
	if filepath.IsAbs(rel) {
		return "", apexerr.Newf(apexerr.CodeUsage, "内部错误：期望相对路径，收到 %q", rel)
	}
	abs := filepath.Join(l.TargetDir, rel)
	if ok, err := withinDir(l.TargetDir, abs); err != nil || !ok {
		return "", apexerr.Newf(apexerr.CodeUsage, "内部错误：路径逃逸 %q", rel)
	}
	return abs, nil
}

// ShardRel returns the "data/YYYY-MM" shard for t (§06.3).
func (l *Layout) ShardRel(t time.Time) string {
	return DataDirName + "/" + t.UTC().Format("2006-01")
}

// NewPackRelName returns a fresh "data/YYYY-MM/pack_<ms>_<6 base36>.dat".
func (l *Layout) NewPackRelName(t time.Time) (string, error) {
	suffix, err := randomBase36(6)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%spack_%d_%s%s", "", t.UTC().UnixMilli(), suffix, PackSuffix)
	return l.ShardRel(t) + "/" + name, nil
}

// JournalName formats a zero-padded journal file name (§03.1, fixed 8 digits).
func (l *Layout) JournalName(seq uint64) string {
	return fmt.Sprintf("%0*d%s", JournalNameWidth, seq, JournalSuffix)
}

// JournalRelPath returns "meta/<seq>.journal".
func (l *Layout) JournalRelPath(seq uint64) string {
	return MetaDirName + "/" + l.JournalName(seq)
}

// ManifestRelPath maps a pack's TargetDir-relative name to its per-pack
// manifest: "meta/manifests/<pack base>.manifest".
func (l *Layout) ManifestRelPath(packName string) string {
	base := strings.TrimSuffix(filepath.Base(filepath.FromSlash(packName)), PackSuffix)
	return MetaDirName + "/" + ManifestDirName + "/" + base + ManifestSuffix
}

// ListManifests returns the manifest file names under meta/manifests, sorted.
func (l *Layout) ListManifests() ([]string, error) {
	entries, err := os.ReadDir(l.ManifestDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法枚举 meta/manifests/")
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ManifestSuffix) {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// ParseJournalName parses a journal file name into its sequence.
func (l *Layout) ParseJournalName(name string) (uint64, bool) {
	if !strings.HasSuffix(name, JournalSuffix) {
		return 0, false
	}
	digits := strings.TrimSuffix(name, JournalSuffix)
	if len(digits) != JournalNameWidth {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	seq, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || seq == 0 {
		return 0, false
	}
	return seq, true
}

// ListPacks returns every pack as a sorted TargetDir-relative path.
func (l *Layout) ListPacks() ([]string, error) {
	var out []string
	err := filepath.WalkDir(l.DataDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), PackSuffix) {
			return nil
		}
		rel, rerr := filepath.Rel(l.TargetDir, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法枚举 data/")
	}
	sort.Strings(out)
	return out, nil
}

// ListJournals returns every journal sequence sorted ascending.
func (l *Layout) ListJournals() ([]uint64, error) {
	entries, err := os.ReadDir(l.MetaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法枚举 meta/")
	}
	var seqs []uint64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if seq, ok := l.ParseJournalName(e.Name()); ok {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}

// MaxSeq returns the highest journal sequence on disk (0 when empty).
func (l *Layout) MaxSeq() (uint64, error) {
	seqs, err := l.ListJournals()
	if err != nil {
		return 0, err
	}
	if len(seqs) == 0 {
		return 0, nil
	}
	return seqs[len(seqs)-1], nil
}

// randomBase36 returns n lowercase base36 characters from the CSPRNG.
func randomBase36(n int) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", apexerr.Wrap(err, apexerr.CodeInternal, "无法生成随机后缀")
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}

// withinDir reports whether abs is dir or inside it (lexical check).
func withinDir(dir, abs string) (bool, error) {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(dirAbs, abs)
	if err != nil {
		return false, nil
	}
	if rel == "." {
		return true, nil
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel), nil
}
