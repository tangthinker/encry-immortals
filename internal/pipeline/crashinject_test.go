package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

type crashEnv struct {
	bin      string
	dir      string
	cfg      string
	vaultDir string
	pwPath   string
	source   string
}

func (e *crashEnv) run(t *testing.T, extraEnv []string, args ...string) (string, int) {
	t.Helper()
	full := append([]string{"--config", e.cfg, "--vault", e.vaultDir, "--password-file", e.pwPath}, args...)
	cmd := exec.Command(e.bin, full...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			t.Fatalf("running %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func newCrashEnv(t *testing.T, bin string, metaBytes []byte, root string) *crashEnv {
	t.Helper()
	dir := filepath.Join(root, "stage-"+fmt.Sprint(time.Now().UnixNano()))
	for _, d := range []string{dir, filepath.Join(dir, "vault"), filepath.Join(dir, "target"), filepath.Join(dir, "source"), filepath.Join(dir, "source", "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "vault", vault.MetaFileName), metaBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pwPath := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwPath, []byte("crash-test-password-123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := "[storage]\n" +
		"target_dir = \"" + filepath.Join(dir, "target") + "\"\n" +
		"slice_plain_bytes = 65536\n" +
		"small_file_bytes = 131072\n" +
		"pack_max_bytes = 1048576\n\n" +
		"[scan]\nexclude = []\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// Source: several files, a multi-slice file, a nested dir and a symlink.
	for name, data := range map[string][]byte{
		"a.txt":     []byte("alpha"),
		"sub/b.txt": []byte("beta"),
		"big.bin":   bytes.Repeat([]byte("0123456789abcdef"), 9000), // 144 KiB > slice size
		"empty":     nil,
	} {
		p := filepath.Join(dir, "source", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "source", "link")); err != nil {
		t.Fatal(err)
	}
	return &crashEnv{bin: bin, dir: dir, cfg: cfgPath, vaultDir: filepath.Join(dir, "vault"), pwPath: pwPath, source: filepath.Join(dir, "source")}
}

// TestCrashInjectionMatrix covers the crash points of spec 12.2 end to end with
// a real binary built with -tags testhooks. Each stage must leave a vault that
// the next run can recover from, and a restore must reproduce the source tree.
func TestCrashInjectionMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("crash injection builds a tagged binary and runs 8 stages")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "apex-testhooks")
	build := exec.Command(goBin, "build", "-tags", "testhooks", "-o", bin, "../../cmd/apex")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build tagged binary: %v\n%s", err, out)
	}

	// One vault.meta shared by all stages (min KDF params keep the test fast).
	meta, err := vault.NewMeta([]byte("crash-test-password-123456"), vaultcrypto.KDFParams{
		Algorithm: vaultcrypto.KDFAlgArgon2id,
		Time:      vaultcrypto.KDFTimeMin,
		MemoryKiB: vaultcrypto.KDFMemoryKiBMin,
		Threads:   4,
		KeyLen:    vaultcrypto.KeyLen,
		Salt:      bytes.Repeat([]byte{0x5c}, vaultcrypto.SaltLen),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	metaBytes, err := meta.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	stages := []string{"K1", "K2", "K3", "K4", "K5", "K6", "K7"}
	for _, stage := range stages {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			e := newCrashEnv(t, bin, metaBytes, t.TempDir())

			out, code := e.run(t, []string{"APEX_TEST_CRASH_AT=" + stage}, "backup", "--source", e.source, "-m", "crash "+stage)
			if code != 137 {
				t.Fatalf("crash injection %s: exit=%d out=%s", stage, code, out)
			}
			// The operator-visible recovery path: the crashed run left its lock.
			out, code = e.run(t, nil, "backup", "--source", e.source, "--break-lock", "-m", "recover "+stage)
			if code != 0 {
				t.Fatalf("recovery backup after %s: exit=%d out=%s", stage, code, out)
			}
			out, code = e.run(t, nil, "doctor", "--chain")
			if code != 0 {
				t.Fatalf("doctor --chain after %s: exit=%d out=%s", stage, code, out)
			}
			dest := filepath.Join(e.dir, "restored")
			out, code = e.run(t, nil, "restore", dest)
			if code != 0 {
				t.Fatalf("restore after %s: exit=%d out=%s", stage, code, out)
			}
			assertTreesEqual(t, e.source, dest)
			want, err := os.ReadFile(filepath.Join(e.source, "a.txt"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("a.txt mismatch after %s: %q vs %q (%v)", stage, got, want, err)
			}
		})
	}

	t.Run("K8", func(t *testing.T) {
		e := newCrashEnv(t, bin, metaBytes, t.TempDir())
		if out, code := e.run(t, nil, "backup", "--source", e.source); code != 0 {
			t.Fatalf("seed backup: exit=%d out=%s", code, out)
		}
		dest := filepath.Join(e.dir, "restored")
		out, code := e.run(t, []string{"APEX_TEST_CRASH_AT=K8"}, "restore", dest)
		if code != 137 {
			t.Fatalf("K8 crash: exit=%d out=%s", code, out)
		}
		// Resume must work with the default overwrite policy: the progress log
		// marks a file, but the resume path re-verifies it before trusting it.
		out, code = e.run(t, nil, "restore", dest)
		if code != 0 {
			t.Fatalf("resume restore: exit=%d out=%s", code, out)
		}
		assertTreesEqual(t, e.source, dest)
		if _, err := os.Stat(filepath.Join(dest, ProgressFileName)); !os.IsNotExist(err) {
			t.Fatal("progress file must be removed after a successful restore")
		}
	})
}

var _ = strings.TrimSpace
