package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

func makeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub/deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub/deep/b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScanBasicTree(t *testing.T) {
	root := makeTree(t)
	res, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Entry{}
	for _, e := range res.Entries {
		byPath[e.Path] = e
	}
	if len(byPath) != 6 {
		t.Fatalf("got %d entries: %v", len(byPath), keys(byPath))
	}
	if e := byPath["a.txt"]; e.Kind != KindFile || e.Size != 1 || e.Mode&0o777 != 0o644 {
		t.Fatalf("a.txt entry wrong: %+v", e)
	}
	if e := byPath["sub"]; e.Kind != KindDir {
		t.Fatalf("sub should be a dir: %+v", e)
	}
	if e := byPath["link"]; e.Kind != KindSymlink || e.LinkTarget != "a.txt" {
		t.Fatalf("link entry wrong: %+v", e)
	}
	if e := byPath["empty"]; e.Kind != KindDir {
		t.Fatalf("empty dir missing: %+v", e)
	}
}

func keys(m map[string]Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestScanExcludes(t *testing.T) {
	root := makeTree(t)
	res, err := Scan(Options{Root: root, Excludes: []string{"sub/**", "*.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Entries {
		if strings.HasPrefix(e.Path, "sub") || strings.HasSuffix(e.Path, ".txt") {
			t.Fatalf("excluded path scanned: %s", e.Path)
		}
	}
	if len(res.Entries) != 2 {
		t.Fatalf("expected link+empty dir, got %v", keys(func() map[string]Entry {
			m := map[string]Entry{}
			for _, e := range res.Entries {
				m[e.Path] = e
			}
			return m
		}()))
	}
}

func TestScanRejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	_, err := Scan(Options{Root: root})
	if err == nil {
		t.Fatal("expected an escaping symlink to be rejected")
	}
	if apexerr.CodeOf(err) != apexerr.CodeUnsupported {
		t.Fatalf("code = %s", apexerr.CodeOf(err))
	}
	// Internal relative links are fine.
	root2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(root2, "target.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root2, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(Options{Root: root2}); err != nil {
		t.Fatalf("internal symlink rejected: %v", err)
	}
}

func TestScanRejectsHardlinkByDefault(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "one.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, filepath.Join(root, "two.txt")); err != nil {
		t.Skip("hardlinks unsupported on this filesystem")
	}
	if _, err := Scan(Options{Root: root}); err == nil {
		t.Fatal("expected a hardlink to fail-fast")
	}
	if _, err := Scan(Options{Root: root, FollowHardlinks: true}); err != nil {
		t.Fatalf("explicit split mode should accept hardlinks: %v", err)
	}
}

func TestScanNormalisesUnicode(t *testing.T) {
	root := t.TempDir()
	decomposed := "cafe\u0301.txt"
	if err := os.WriteFile(filepath.Join(root, decomposed), []byte("x"), 0o644); err != nil {
		t.Skip("filesystem rejects decomposed names")
	}
	res, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d", len(res.Entries))
	}
	if res.Entries[0].Path != "caf\u00e9.txt" {
		t.Fatalf("path not NFC-normalised: %q", res.Entries[0].Path)
	}
}

func TestExcludedPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{".git/**", ".git/config", true},
		{".git/**", ".git", true},
		{".git/**", "sub/.git/config", false},
		{"*.tmp", "a/b/c.tmp", true},
		{"*.tmp", "a/b/c.txt", false},
		{"node_modules/**", "node_modules/x/y.js", true},
		{"docs/*.md", "docs/readme.md", true},
		{"docs/*.md", "docs/sub/readme.md", false},
	}
	for _, c := range cases {
		if got := Excluded([]string{c.pattern}, c.path); got != c.want {
			t.Errorf("Excluded(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}
