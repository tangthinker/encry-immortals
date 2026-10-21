package store

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func newTestLayout(t *testing.T) *Layout {
	t.Helper()
	l, err := NewLayout(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLayoutEnsureAndWhitelist(t *testing.T) {
	l := newTestLayout(t)
	for _, dir := range []string{l.TargetDir, l.DataDir, l.MetaDir, l.StagingDir} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("%s is not a directory: %v", dir, err)
		}
	}
	if err := l.ValidateTopLevel(); err != nil {
		t.Fatalf("clean target rejected: %v", err)
	}
	// macOS Finder creates .DS_Store without asking; it is not pollution.
	if err := os.WriteFile(filepath.Join(l.RootDir, FinderMetadataFileName), []byte("finder"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateTopLevel(); err != nil {
		t.Fatalf("Finder metadata should be ignored: %v", err)
	}
	if err := os.WriteFile(filepath.Join(l.RootDir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateTopLevel(); err == nil {
		t.Fatal("expected TargetDir pollution to be rejected")
	}
}

func TestPackAndJournalNames(t *testing.T) {
	l := newTestLayout(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	rel, err := l.NewPackRelName(now)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^data/2026-10/pack_[0-9]{13}_[0-9a-z]{6}\.dat$`)
	if !re.MatchString(rel) {
		t.Fatalf("pack name %q does not match the required pattern", rel)
	}
	other, err := l.NewPackRelName(now)
	if err != nil {
		t.Fatal(err)
	}
	if rel == other {
		t.Fatal("pack names must be unique")
	}

	if got := l.JournalName(1); got != "00000001.journal" {
		t.Fatalf("JournalName(1) = %q", got)
	}
	if got := l.JournalName(99999999); got != "99999999.journal" {
		t.Fatalf("JournalName(max) = %q", got)
	}
	if seq, ok := l.ParseJournalName("00000007.journal"); !ok || seq != 7 {
		t.Fatalf("ParseJournalName = %d, %v", seq, ok)
	}
	for _, bad := range []string{"7.journal", "00000000.journal", "0000000a.journal", "00000007.dat", "000000007.journal"} {
		if _, ok := l.ParseJournalName(bad); ok {
			t.Errorf("ParseJournalName(%q) accepted an invalid name", bad)
		}
	}
}

func TestListJournalsAndMaxSeq(t *testing.T) {
	l := newTestLayout(t)
	for _, seq := range []uint64{2, 1, 100} {
		if err := os.WriteFile(filepath.Join(l.MetaDir, l.JournalName(seq)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seqs, err := l.ListJournals()
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 3 || seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 100 {
		t.Fatalf("ListJournals = %v", seqs)
	}
	if max, err := l.MaxSeq(); err != nil || max != 100 {
		t.Fatalf("MaxSeq = %d, %v", max, err)
	}
}

func TestSweepStaging(t *testing.T) {
	l := newTestLayout(t)
	old := filepath.Join(l.StagingDir, "pack_1_aaaaaa.dat")
	fresh := filepath.Join(l.StagingDir, "pack_2_bbbbbb.dat")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("junk"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	removed, bytes, err := SweepStaging(l.StagingDir, time.Now().Unix(), 24*3600)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || bytes != 4 {
		t.Fatalf("SweepStaging removed %d files / %d bytes", removed, bytes)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old staging file was not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh staging file must survive")
	}
}

func TestWriteFileDurable(t *testing.T) {
	l := newTestLayout(t)
	final := filepath.Join(l.MetaDir, "00000001.journal")
	if err := WriteFileDurable(l.StagingDir, final, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(final)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	entries, err := os.ReadDir(l.StagingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging directory should be empty, has %d entries", len(entries))
	}
}
func TestLayoutAcceptsLegacyLockName(t *testing.T) {
	l := newTestLayout(t)
	if err := os.WriteFile(filepath.Join(l.RootDir, LegacyLockFileName), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateTopLevel(); err != nil {
		t.Fatalf("legacy lock file must not be reported as pollution: %v", err)
	}
}

func TestRootLayoutPaths(t *testing.T) {
	root := t.TempDir()
	l, err := NewLayout(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if l.UsesOutputDir() {
		t.Fatal("an empty TargetDir must use the root layout")
	}
	if l.RootDir != root || l.TargetDir != root {
		t.Fatalf("unexpected roots: %+v", l)
	}
	if l.DataDir != filepath.Join(root, DataDirName) ||
		l.MetaDir != filepath.Join(root, MetaDirName) ||
		l.StagingDir != root+StagingDirName {
		t.Fatalf("unexpected paths: %+v", l)
	}
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{l.RootDir, l.DataDir, l.MetaDir, l.StagingDir} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("%s missing: %v", dir, err)
		}
	}
	if err := l.ValidateTopLevel(); err != nil {
		t.Fatalf("root layout rejected: %v", err)
	}
	if err := l.ValidateStagingVolume(); err != nil {
		t.Fatalf("sibling staging should share the target volume: %v", err)
	}
}

func TestOutputCompatDetection(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, OutputDirName, DataDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, OutputDirName, MetaDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := NewLayout(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if !l.UsesOutputDir() || l.TargetDir != filepath.Join(root, OutputDirName) {
		t.Fatalf("output compatibility layout not detected: %+v", l)
	}
	if l.StagingDir != root+StagingDirName {
		t.Fatalf("staging dir = %s", l.StagingDir)
	}
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateTopLevel(); err != nil {
		t.Fatalf("output compatibility layout rejected: %v", err)
	}
}
