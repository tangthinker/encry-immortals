package pipeline

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tangthinker/encry-immortals/internal/config"
	"github.com/tangthinker/encry-immortals/internal/store"
)

// TestPerformanceBaseline is the spec 12.7 smoke measurement. It is opt-in
// because it writes ~128 MiB: EIMMORTAL_PERF_TEST=1 go test ./internal/pipeline -run TestPerformanceBaseline -v
func TestPerformanceBaseline(t *testing.T) {
	if os.Getenv("EIMMORTAL_PERF_TEST") == "" {
		t.Skip("set EIMMORTAL_PERF_TEST=1 to run the performance baseline")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	const (
		files    = 128
		fileSize = 1 << 20 // 1 MiB; pseudo-random, i.e. incompressible
	)
	buf := make([]byte, fileSize)
	for i := 0; i < files; i++ {
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, fmt.Sprintf("f%03d.bin", i)), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	layout, err := store.NewLayout(filepath.Join(root, "target"), "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Storage.SlicePlainBytes = 8 << 20
	cfg.Storage.SmallFileBytes = 16 << 20
	cfg.Storage.PackMaxBytes = 128 << 20
	cfg.Scan.Exclude = nil

	start := time.Now()
	res, err := Backup(BackupOptions{Layout: layout, Keys: testKeys, Config: cfg, SourceDir: source, Message: "perf"})
	if err != nil {
		t.Fatal(err)
	}
	backupDur := time.Since(start)
	if !res.Changed {
		t.Fatal("backup did not commit")
	}
	logical := float64(files*fileSize) / (1 << 20)
	t.Logf("backup:   %.1f MiB in %s = %.1f MiB/s (packs %d, %.1f MiB on disk)",
		logical, backupDur.Round(time.Millisecond), logical/backupDur.Seconds(),
		len(res.Packs), float64(res.PackBytes)/(1<<20))

	dest := filepath.Join(root, "restored")
	start = time.Now()
	rr, err := Restore(RestoreOptions{
		Layout: layout, Keys: testKeys, Config: cfg, DestDir: dest, Overwrite: OverwriteNever,
	})
	if err != nil {
		t.Fatal(err)
	}
	restoreDur := time.Since(start)
	logicalOut := float64(rr.Bytes) / (1 << 20)
	t.Logf("restore:  %.1f MiB in %s = %.1f MiB/s", logicalOut, restoreDur.Round(time.Millisecond), logicalOut/restoreDur.Seconds())

	start = time.Now()
	if _, err := journalLoadForPerf(layout); err != nil {
		t.Fatal(err)
	}
	t.Logf("chain load for restore startup: %s", time.Since(start).Round(time.Millisecond))
}
