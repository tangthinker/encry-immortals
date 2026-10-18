package pipeline

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRestoreProgressReports(t *testing.T) {
	var lines []string
	now := time.Unix(1000, 0)
	r := &restoreRun{
		opts: RestoreOptions{
			Progress: func(format string, args ...any) {
				lines = append(lines, fmt.Sprintf(format, args...))
			},
			Now: func() time.Time { return now },
		},
		totalFiles: 2,
		totalBytes: 2 << 20,
	}

	r.reportProgress(0, 0, "a.bin", true)
	now = now.Add(100 * time.Millisecond)
	r.reportProgress(1, 1<<20, "b.bin", false) // throttled: same second
	now = now.Add(2 * time.Second)
	r.reportProgress(1, 1<<20, "b.bin", false)
	r.reportProgress(2, 2<<20, "", true)

	if len(lines) != 3 {
		t.Fatalf("progress lines = %q, want 3", lines)
	}
	for _, want := range []string{"0/2", "当前 a.bin"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("first line %q missing %q", lines[0], want)
		}
	}
	for _, want := range []string{"1/2", "50%", "当前 b.bin"} {
		if !strings.Contains(lines[1], want) {
			t.Fatalf("progress line %q missing %q", lines[1], want)
		}
	}
	for _, want := range []string{"2/2", "100%"} {
		if !strings.Contains(lines[2], want) {
			t.Fatalf("final line %q missing %q", lines[2], want)
		}
	}
}
