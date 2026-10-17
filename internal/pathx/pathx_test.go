package pathx

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"a":             "a",
		"a/b.txt":       "a/b.txt",
		"photos/2026/a": "photos/2026/a",
		"a b/c d.txt":   "a b/c d.txt",
		"dir/sub/../x":  "",
		"a\\b":          "a/b",
	}
	delete(ok, "dir/sub/../x")
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}

	bad := []string{
		"",
		"/abs/path",
		"a//b",
		"a/./b",
		"a/../b",
		"../a",
		"c:/windows",
		"a\x00b",
		strings.Repeat("a", 256),
		"ok/" + strings.Repeat("b", 256),
		string([]byte{0xff, 0xfe}),
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", in, got)
		}
	}
}

func TestNormalizeAppliesNFC(t *testing.T) {
	decomposed := "cafe\u0301.txt" // e + combining acute
	got, err := Normalize(decomposed)
	if err != nil {
		t.Fatal(err)
	}
	want := "caf\u00e9.txt"
	if got != want {
		t.Fatalf("Normalize(%q) = %q, want %q", decomposed, got, want)
	}
	// idempotent
	again, err := Normalize(got)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Fatalf("Normalize is not idempotent: %q -> %q", got, again)
	}
}

func TestCheckWindowsSegment(t *testing.T) {
	for _, seg := range []string{"CON", "nul.txt", "Com1", "aux.tar.gz", "a.", "a "} {
		if err := CheckWindowsSegment(seg); err == nil {
			t.Errorf("CheckWindowsSegment(%q) accepted a reserved/invalid name", seg)
		}
	}
	for _, seg := range []string{"console", "com10", "a.b", "正常文件名"} {
		if err := CheckWindowsSegment(seg); err != nil {
			t.Errorf("CheckWindowsSegment(%q): %v", seg, err)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	got, err := SafeJoin(root, "a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "a", "b.txt")
	if got != want {
		t.Fatalf("SafeJoin = %q, want %q", got, want)
	}
	for _, rel := range []string{"../x", "/etc/passwd", "a/../../x", ""} {
		if _, err := SafeJoin(root, rel); err == nil {
			t.Errorf("SafeJoin(%q) accepted an escaping path", rel)
		}
	}
}

func TestContainsAndOverlap(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "x", "y")
	if ok, err := Contains(root, inside); err != nil || !ok {
		t.Fatalf("Contains(%q, %q) = %v, %v", root, inside, ok, err)
	}
	if ok, err := Contains(root, filepath.Dir(root)); err != nil || ok {
		t.Fatalf("parent directory reported as contained")
	}
	if ok, err := Overlap(root, inside); err != nil || !ok {
		t.Fatalf("Overlap(parent, child) = %v, %v", ok, err)
	}
	other := t.TempDir()
	if ok, err := Overlap(root, other); err != nil || ok {
		t.Fatalf("independent temp dirs reported as overlapping")
	}
}

func TestCaseFoldConflicts(t *testing.T) {
	if _, _, ok := CaseFoldConflicts([]string{"a.txt", "b.txt", "A.txt"}); !ok {
		// "a.txt" and "A.txt" collide
		t.Fatal("expected a case-fold conflict")
	}
	if _, _, ok := CaseFoldConflicts([]string{"a.txt", "b.txt", "c.txt"}); ok {
		t.Fatal("unexpected case-fold conflict")
	}
	if _, _, ok := CaseFoldConflicts([]string{"a.txt", "a.txt"}); ok {
		t.Fatal("duplicate identical paths must not be a conflict")
	}
}

func TestDepthAndParent(t *testing.T) {
	if Depth("a/b/c") != 3 || Depth("a") != 1 || Depth("") != 0 {
		t.Fatal("Depth mismatch")
	}
	if Parent("a/b/c") != "a/b" || Parent("a") != "" {
		t.Fatal("Parent mismatch")
	}
}
