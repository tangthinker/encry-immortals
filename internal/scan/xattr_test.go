//go:build linux || darwin

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

func TestScanRejectsXattrsByDefault(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tagged.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(path, "com.apex.test", []byte("1"), 0); err != nil {
		t.Skipf("cannot set xattr on this filesystem: %v", err)
	}
	if _, err := Scan(Options{Root: root}); err == nil {
		t.Fatal("expected an xattr to fail-fast")
	} else if apexerr.CodeOf(err) != apexerr.CodeUnsupported {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeUnsupported)
	}
	res, err := Scan(Options{Root: root, IgnoreXattr: true})
	if err != nil {
		t.Fatalf("ignore_xattr should allow the scan: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d", len(res.Entries))
	}
}
