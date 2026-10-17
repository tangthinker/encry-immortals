// Package pathx owns every path policy that is platform dependent:
// NFC normalisation, ingestion validation, case-fold collision detection and
// zip-slip-safe joins (spec 05.6 / 09.6 / ADR-013).
//
// Structural, platform-independent rules (no "..", no absolute paths, UTF-8,
// length caps) are also enforced by the wire decoder; this package is the
// authoritative entry point for data we are about to write.
package pathx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Limits fixed by spec §09.6.
const (
	MaxSegmentBytes = 255
	MaxPathBytes    = 4096
)

var (
	// ErrEmpty is returned for an empty path.
	ErrEmpty = errors.New("pathx: empty path")
	// ErrUnsafe is returned for paths that could escape a root.
	ErrUnsafe = errors.New("pathx: unsafe path")
)

// Normalize canonicalises a source-relative path for ingestion:
//   - rejects empty, invalid UTF-8, NUL
//   - converts backslashes to '/'
//   - rejects absolute paths and Windows drive letters
//   - applies NFC
//   - rejects "", "." and ".." segments and over-long segments
func Normalize(p string) (string, error) {
	if p == "" {
		return "", ErrEmpty
	}
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("pathx: invalid UTF-8: %q", p)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("pathx: NUL in path")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("pathx: absolute path: %q", p)
	}
	if len(p) >= 2 && p[1] == ':' {
		return "", fmt.Errorf("pathx: drive-letter path: %q", p)
	}
	p = norm.NFC.String(p)
	if len(p) > MaxPathBytes {
		return "", fmt.Errorf("pathx: path longer than %d bytes", MaxPathBytes)
	}
	segments := strings.Split(p, "/")
	for _, seg := range segments {
		switch seg {
		case "":
			return "", fmt.Errorf("pathx: empty segment in %q", p)
		case ".", "..":
			return "", fmt.Errorf("pathx: relative segment %q in %q", seg, p)
		}
		if len(seg) > MaxSegmentBytes {
			return "", fmt.Errorf("pathx: segment longer than %d bytes", MaxSegmentBytes)
		}
		if err := checkPlatformSegment(seg); err != nil {
			return "", err
		}
	}
	return strings.Join(segments, "/"), nil
}

// checkPlatformSegment rejects names that the current platform cannot create.
func checkPlatformSegment(seg string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	if err := CheckWindowsSegment(seg); err != nil {
		return err
	}
	return nil
}

// CheckWindowsSegment reports Windows name restrictions. It is exported so the
// rules can be unit tested on any platform.
func CheckWindowsSegment(seg string) error {
	if strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, ".") {
		return fmt.Errorf("pathx: Windows forbids trailing space or dot: %q", seg)
	}
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return fmt.Errorf("pathx: Windows reserved name: %q", seg)
	}
	return nil
}

// SafeJoin resolves rel inside root and guarantees the result stays inside root.
// It calls Normalize first, so a path that needs sanitising is an error, never a
// silent rewrite (05.6: refuse rather than surprise the user).
func SafeJoin(root, rel string) (string, error) {
	clean, err := Normalize(rel)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(rootAbs, filepath.FromSlash(clean))
	back, err := filepath.Rel(rootAbs, joined)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrUnsafe, rel)
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(os.PathSeparator)) || filepath.IsAbs(back) {
		return "", fmt.Errorf("%w: %q escapes %s", ErrUnsafe, rel, root)
	}
	return joined, nil
}

// Contains reports whether child is root or lies below it, after resolving both
// to absolute lexical paths (symlinks are deliberately not followed).
func Contains(root, child string) (bool, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	childAbs, err := filepath.Abs(child)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(rootAbs, childAbs)
	if err != nil {
		return false, nil
	}
	if rel == "." {
		return true, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}
	return !filepath.IsAbs(rel), nil
}

// Overlap reports whether two directory trees overlap in either direction.
// Used to forbid TargetDir inside SourceDir (spec 01.8).
func Overlap(a, b string) (bool, error) {
	ab, err := Contains(a, b)
	if err != nil {
		return false, err
	}
	if ab {
		return true, nil
	}
	return Contains(b, a)
}

// CaseFoldConflicts returns the first pair of distinct paths that collide when
// case-folded. Only used on case-insensitive filesystems, but computed on all
// platforms because the conflict is a property of the data set, not the host
// (spec 01.6, D-18).
func CaseFoldConflicts(paths []string) (first, second string, ok bool) {
	seen := make(map[string]string, len(paths))
	for _, p := range paths {
		key := strings.ToLower(p)
		if prev, exists := seen[key]; exists && prev != p {
			return prev, p, true
		}
		seen[key] = p
	}
	return "", "", false
}

// Depth returns the number of path segments, used to order directory creation.
func Depth(p string) int {
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// Parent returns the parent of a relative path, or "" for a top-level entry.
func Parent(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return ""
	}
	return p[:i]
}
