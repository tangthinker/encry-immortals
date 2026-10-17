package lock

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

func TestControlLockExcludesSecondHolder(t *testing.T) {
	dir := t.TempDir()
	l1, err := AcquireControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireControl(dir); err == nil {
		t.Fatal("expected the second acquisition to fail")
	} else if apexerr.CodeOf(err) != apexerr.CodeLocked {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeLocked)
	}
	if err := l1.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := AcquireControl(dir)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := l2.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestTargetLockLifecycle(t *testing.T) {
	dir := t.TempDir()
	info := NewTargetInfo("test-1")
	lk, err := AcquireTargetLock(dir, info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, TargetLockName)); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
	if _, err := AcquireTargetLock(dir, info); err == nil {
		t.Fatal("expected the second target lock to fail")
	} else if apexerr.CodeOf(err) != apexerr.CodeLocked {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeLocked)
	}
	got, err := ReadTargetLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostID != info.HostID || got.PID != info.PID || got.ToolVersion != "test-1" {
		t.Fatalf("lock record mismatch: %+v", got)
	}
	if err := lk.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, TargetLockName)); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed")
	}
	lk2, err := AcquireTargetLock(dir, info)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := BreakTargetLock(dir); err != nil {
		t.Fatal(err)
	}
	if err := lk2.Release(); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestLegacyTargetLockIsRespectedAndBreakable(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, LegacyTargetLockName)
	if err := os.WriteFile(legacy, []byte(`{"host_id":"old-host"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireTargetLock(dir, NewTargetInfo("new")); err == nil {
		t.Fatal("a legacy .apex.lock must still block a new writer")
	} else if apexerr.CodeOf(err) != apexerr.CodeLocked {
		t.Fatalf("code = %s, want %s", apexerr.CodeOf(err), apexerr.CodeLocked)
	}
	if err := BreakTargetLock(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("break-lock must remove the legacy lock file")
	}
	lk, err := AcquireTargetLock(dir, NewTargetInfo("new"))
	if err != nil {
		t.Fatalf("acquire after break-lock: %v", err)
	}
	if err := lk.Release(); err != nil {
		t.Fatal(err)
	}
}
