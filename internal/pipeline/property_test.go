package pipeline

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// TestRandomTreeRoundTrip is the property test from spec 12.5: a random tree
// evolves over several commits; every snapshot must restore byte-for-byte.
func TestRandomTreeRoundTrip(t *testing.T) {
	e := newEnv(t)
	rnd := rand.New(rand.NewSource(20261017))
	files := map[string][]byte{}
	snapshots := map[uint64]map[string][]byte{}
	clone := func(in map[string][]byte) map[string][]byte {
		out := make(map[string][]byte, len(in))
		for k, v := range in {
			out[k] = append([]byte(nil), v...)
		}
		return out
	}
	randomData := func(max int) []byte {
		n := rnd.Intn(max)
		b := make([]byte, n)
		rnd.Read(b)
		return b
	}
	keys := func() []string {
		out := make([]string, 0, len(files))
		for k := range files {
			out = append(out, k)
		}
		return out
	}

	commits := 0
	for step := 0; step < 12; step++ {
		switch rnd.Intn(3) {
		case 0: // add
			name := fmt.Sprintf("d%d/f%02d.bin", rnd.Intn(3), rnd.Intn(40))
			files[name] = randomData(4000)
		case 1: // modify
			if ks := keys(); len(ks) > 0 {
				files[ks[rnd.Intn(len(ks))]] = randomData(6000)
			}
		case 2: // delete
			if ks := keys(); len(ks) > 0 {
				delete(files, ks[rnd.Intn(len(ks))])
			}
		}
		// Apply to disk: write every file, remove files that no longer exist.
		if err := syncTree(e.source, files); err != nil {
			t.Fatal(err)
		}
		res := e.backup(t, false)
		if !res.Changed {
			continue
		}
		commits++
		snapshots[res.Seq] = clone(files)
	}
	if commits == 0 {
		t.Fatal("property test produced no commits")
	}

	// Latest snapshot.
	latest := filepath.Join(e.root, "restore-latest")
	e.restore(t, latest, 0)
	compareFiles(t, snapshots[uint64(commits)], latest)

	// A middle snapshot exercises replay + truncation at an arbitrary point.
	if commits >= 3 {
		target := uint64(1 + rnd.Intn(commits-1))
		dest := filepath.Join(e.root, fmt.Sprintf("restore-at-%d", target))
		e.restore(t, dest, target)
		compareFiles(t, snapshots[target], dest)
	}
}

func syncTree(root string, files map[string][]byte) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	// Remove files that vanished.
	walkErr := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if _, ok := files[filepath.ToSlash(rel)]; !ok {
			return os.Remove(p)
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	for name, data := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func compareFiles(t *testing.T, want map[string][]byte, dir string) {
	t.Helper()
	seen := 0
	for name, data := range want {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("missing %s in %s: %v", name, dir, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s content mismatch (len %d vs %d)", name, len(got), len(data))
		}
		seen++
	}
	extra := 0
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if _, ok := want[filepath.ToSlash(rel)]; !ok {
			extra++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if extra != 0 {
		t.Fatalf("%d unexpected files in %s (restored more than the snapshot)", extra, dir)
	}
	if seen != len(want) {
		t.Fatalf("compared %d of %d files", seen, len(want))
	}
}
