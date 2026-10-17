package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

const testPassword = "cli-test-password-123456"

type cliEnv struct {
	root     string
	cfgPath  string
	vaultDir string
	target   string
	source   string
	pwPath   string
	app      *App
}

func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	root := t.TempDir()
	env := &cliEnv{
		root:     root,
		cfgPath:  filepath.Join(root, "config.toml"),
		vaultDir: filepath.Join(root, "vault"),
		target:   filepath.Join(root, "target"),
		source:   filepath.Join(root, "source"),
		pwPath:   filepath.Join(root, "password"),
	}
	for _, d := range []string{env.vaultDir, env.target, env.source} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Pre-provision a vault at the spec lower bound so tests are fast.
	params := vaultcrypto.KDFParams{
		Algorithm: vaultcrypto.KDFAlgArgon2id,
		Time:      vaultcrypto.KDFTimeMin,
		MemoryKiB: vaultcrypto.KDFMemoryKiBMin,
		Threads:   4,
		KeyLen:    vaultcrypto.KeyLen,
		Salt:      bytes.Repeat([]byte{0x21}, vaultcrypto.SaltLen),
	}
	meta, err := vault.NewMeta([]byte(testPassword), params, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.Save(env.vaultDir); err != nil {
		t.Fatal(err)
	}
	cfg := "[storage]\n" +
		"target_dir = \"" + env.target + "\"\n" +
		"slice_plain_bytes = 65536\n" +
		"small_file_bytes = 131072\n" +
		"pack_max_bytes = 1048576\n\n" +
		"[scan]\nexclude = []\n"
	if err := os.WriteFile(env.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.pwPath, []byte(testPassword), 0o600); err != nil {
		t.Fatal(err)
	}
	env.app = &App{Stdin: os.Stdin}
	return env
}

func (e *cliEnv) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	e.app.Stdout = &out
	e.app.Stderr = &errb
	full := append([]string{
		"--config", e.cfgPath, "--vault", e.vaultDir, "--password-file", e.pwPath,
	}, args...)
	code := e.app.Run(full)
	return out.String(), errb.String(), code
}

func (e *cliEnv) writeSource(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.source, "a.txt"), []byte("hello apex"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.source, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.source, "sub", "b.txt"), []byte("nested"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(e.source, "link")); err != nil {
		t.Fatal(err)
	}
}

func TestCLIBackupRestoreFlow(t *testing.T) {
	env := newCLIEnv(t)
	env.writeSource(t)

	out, _, code := env.run(t, "backup", "--source", env.source, "-m", "first")
	if code != 0 {
		t.Fatalf("backup exit = %d, out=%q", code, out)
	}
	if !bytes.Contains([]byte(out), []byte("已提交 seq=1")) {
		t.Fatalf("unexpected backup output: %q", out)
	}

	out, _, code = env.run(t, "backup", "--source", env.source)
	if code != 0 || !bytes.Contains([]byte(out), []byte("no changes")) {
		t.Fatalf("second backup: code=%d out=%q", code, out)
	}

	out, _, code = env.run(t, "log", "--json")
	if code != 0 {
		t.Fatalf("log exit = %d", code)
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("log --json is not valid JSON: %v\n%s", err, out)
	}
	if len(entries) != 1 {
		t.Fatalf("log returned %d entries", len(entries))
	}

	out, _, code = env.run(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status exit = %d", code)
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("status --json invalid: %v\n%s", err, out)
	}
	if status["schema"].(float64) != 1 {
		t.Fatalf("status schema = %v", status["schema"])
	}
	if status["last_seq"].(float64) != 1 {
		t.Fatalf("status last_seq = %v", status["last_seq"])
	}

	dest := filepath.Join(env.root, "restored")
	out, errOut, code := env.run(t, "restore", dest)
	if code != 0 {
		t.Fatalf("restore exit = %d out=%q err=%q", code, out, errOut)
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || string(got) != "hello apex" {
		t.Fatalf("restored content = %q, %v", got, err)
	}
	if link, err := os.Readlink(filepath.Join(dest, "link")); err != nil || link != "a.txt" {
		t.Fatalf("restored symlink = %q, %v", link, err)
	}

	out, _, code = env.run(t, "verify", "--deep", "--json")
	if code != 0 {
		t.Fatalf("verify exit = %d out=%q", code, out)
	}
	var verifyDoc map[string]any
	if err := json.Unmarshal([]byte(out), &verifyDoc); err != nil {
		t.Fatalf("verify --json invalid: %v", err)
	}
	if failures := verifyDoc["deep_failures"]; failures != nil {
		if arr, ok := failures.([]any); ok && len(arr) > 0 {
			t.Fatalf("deep verification failures: %v", arr)
		}
	}
}

func TestCLISnapshotTravelWithTrailingFlags(t *testing.T) {
	env := newCLIEnv(t)
	env.writeSource(t)
	if _, _, code := env.run(t, "backup", "--source", env.source); code != 0 {
		t.Fatal("backup 1 failed")
	}
	if err := os.WriteFile(filepath.Join(env.source, "a.txt"), []byte("v2 content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := env.run(t, "backup", "--source", env.source); code != 0 {
		t.Fatal("backup 2 failed")
	}

	// Flags after the positional argument must still be honoured.
	out, _, code := env.run(t, "cat", "a.txt", "--at", "1")
	if code != 0 {
		t.Fatalf("cat --at exit = %d", code)
	}
	if out != "hello apex" {
		t.Fatalf("cat --at 1 = %q, want the seq=1 content", out)
	}
	out, _, code = env.run(t, "cat", "a.txt", "--at", "2")
	if code != 0 || out != "v2 content" {
		t.Fatalf("cat --at 2 = %q (exit %d)", out, code)
	}

	dest := filepath.Join(env.root, "at1")
	if _, _, code := env.run(t, "restore", dest, "--at", "1"); code != 0 {
		t.Fatalf("restore --at exit = %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || string(got) != "hello apex" {
		t.Fatalf("restore --at 1 content = %q, %v", got, err)
	}
}

func TestCLIExitCodes(t *testing.T) {
	env := newCLIEnv(t)
	if _, _, code := env.run(t, "no-such-command"); code != apexerr.ExitUsage {
		t.Fatalf("unknown command exit = %d, want %d", code, apexerr.ExitUsage)
	}
	// Wrong password -> E10.
	if err := os.WriteFile(env.pwPath, []byte("wrong-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := env.run(t, "log"); code != apexerr.ExitUnlock {
		t.Fatalf("wrong password exit = %d, want %d", code, apexerr.ExitUnlock)
	}
	// Restore into a non-empty destination -> E2.
	env2 := newCLIEnv(t)
	env2.writeSource(t)
	if _, _, code := env2.run(t, "backup", "--source", env2.source); code != 0 {
		t.Fatal("backup failed")
	}
	busy := filepath.Join(env2.root, "busy")
	if err := os.MkdirAll(busy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(busy, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := env2.run(t, "restore", busy); code != apexerr.ExitUsage {
		t.Fatalf("non-empty dest exit = %d, want %d", code, apexerr.ExitUsage)
	}
}

func TestCLIExportImportKey(t *testing.T) {
	env := newCLIEnv(t)
	out, _, code := env.run(t, "export-key", "--json")
	if code != 0 {
		t.Fatalf("export-key exit = %d", code)
	}
	var doc struct {
		Armor   string `json:"armor"`
		Grouped string `json:"grouped"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("export-key --json invalid: %v", err)
	}
	if len(doc.Armor) < 40 || doc.Grouped == "" {
		t.Fatalf("armor output too short: %d", len(doc.Armor))
	}
	keyFile := filepath.Join(env.root, "armor.txt")
	if err := os.WriteFile(keyFile, []byte(doc.Grouped), 0o600); err != nil {
		t.Fatal(err)
	}
	// Replace the control plane with a fresh one and import the key back.
	if err := os.Remove(filepath.Join(env.vaultDir, vault.MetaFileName)); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := env.run(t, "import-key", "--key-file", keyFile); code != 0 {
		t.Fatalf("import-key exit = %d err=%q", code, errOut)
	}
	if _, _, code := env.run(t, "log"); code != 0 {
		t.Fatalf("imported vault cannot be unlocked")
	}
}

func TestCLIDoctorStructural(t *testing.T) {
	env := newCLIEnv(t)
	env.writeSource(t)
	if _, _, code := env.run(t, "backup", "--source", env.source); code != 0 {
		t.Fatal("backup failed")
	}
	out, _, code := env.run(t, "doctor", "--chain", "--json")
	if code != 0 {
		t.Fatalf("doctor exit = %d out=%q", code, out)
	}
	var checks []map[string]any
	if err := json.Unmarshal([]byte(out), &checks); err != nil {
		t.Fatalf("doctor --json invalid: %v", err)
	}
	for _, c := range checks {
		if c["status"] == "FAIL" {
			t.Fatalf("doctor reported FAIL: %v", c)
		}
	}
}

func TestCLIInitCreatesVault(t *testing.T) {
	if testing.Short() {
		t.Skip("init runs real Argon2id calibration")
	}
	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.toml")
	cfg := "[storage]\ntarget_dir = \"" + filepath.Join(root, "target") + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	pwPath := filepath.Join(root, "pw")
	if err := os.WriteFile(pwPath, []byte("init-test-password-123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := &App{Stdin: os.Stdin}
	var out, errb bytes.Buffer
	app.Stdout = &out
	app.Stderr = &errb
	code := app.Run([]string{"--config", cfgPath, "--vault", filepath.Join(root, "vault"), "--password-file", pwPath, "init"})
	if code != 0 {
		t.Fatalf("init exit = %d, stderr=%q", code, errb.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("APEX-KEY-V2-")) {
		t.Fatalf("init did not print an Armor Key")
	}
	if _, err := os.Stat(filepath.Join(root, "vault", vault.RecoveryFileName)); err != nil {
		t.Fatalf("RECOVERY.txt missing: %v", err)
	}
}

// TestCLIDisasterRecoveryDrill walks the exact flow of spec 07.4: export the
// Armor Key, simulate a new machine with a fresh control plane, import the key,
// verify and restore.
func TestCLIDisasterRecoveryDrill(t *testing.T) {
	env := newCLIEnv(t)
	env.writeSource(t)
	if _, _, code := env.run(t, "backup", "--source", env.source, "-m", "before disaster"); code != 0 {
		t.Fatal("seed backup failed")
	}
	out, _, code := env.run(t, "status", "--json")
	if code != 0 {
		t.Fatal("status failed")
	}
	var origStatus struct {
		VaultID string `json:"vault_id"`
	}
	if err := json.Unmarshal([]byte(out), &origStatus); err != nil {
		t.Fatal(err)
	}

	// 1. The operator saves the Armor Key somewhere outside the synced folder.
	out, _, code = env.run(t, "export-key", "--json")
	if code != 0 {
		t.Fatal("export-key failed")
	}
	var armorDoc struct {
		Armor string `json:"armor"`
	}
	if err := json.Unmarshal([]byte(out), &armorDoc); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(env.root, "armor.txt")
	if err := os.WriteFile(keyFile, []byte(armorDoc.Armor), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. New machine: fresh control plane, the TargetDir came from the cloud.
	newVault := filepath.Join(env.root, "vault-new-machine")
	var outBuf, errBuf bytes.Buffer
	app := &App{Stdin: os.Stdin}
	app.Stdout = &outBuf
	app.Stderr = &errBuf
	run := func(args ...string) int {
		outBuf.Reset()
		errBuf.Reset()
		full := append([]string{
			"--config", env.cfgPath, "--vault", newVault, "--password-file", env.pwPath,
		}, args...)
		return app.Run(full)
	}

	if code := run("init", "--join", env.target); code != 0 {
		t.Fatalf("init --join: exit=%d err=%s", code, errBuf.String())
	}
	if code := run("import-key", "--key-file", keyFile); code != 0 {
		t.Fatalf("import-key: exit=%d err=%s", code, errBuf.String())
	}
	if code := run("status", "--json"); code != 0 {
		t.Fatalf("status on the recovered vault: %s", errBuf.String())
	}
	var newStatus struct {
		VaultID string `json:"vault_id"`
	}
	if err := json.Unmarshal(outBuf.Bytes(), &newStatus); err != nil {
		t.Fatal(err)
	}
	if newStatus.VaultID != origStatus.VaultID {
		t.Fatalf("vault_id changed across recovery: %s != %s", newStatus.VaultID, origStatus.VaultID)
	}
	if code := run("verify", "--size"); code != 0 {
		t.Fatalf("verify --size: exit=%d err=%s", code, errBuf.String())
	}
	dest := filepath.Join(env.root, "dr-restored")
	if code := run("restore", dest); code != 0 {
		t.Fatalf("restore: exit=%d err=%s", code, errBuf.String())
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || string(got) != "hello apex" {
		t.Fatalf("recovered content = %q, %v", got, err)
	}
	if link, err := os.Readlink(filepath.Join(dest, "link")); err != nil || link != "a.txt" {
		t.Fatalf("recovered symlink = %q, %v", link, err)
	}
}
func TestCLIStatusChainAndWaitForPacks(t *testing.T) {
	env := newCLIEnv(t)
	env.writeSource(t)
	if _, _, code := env.run(t, "backup", "--source", env.source); code != 0 {
		t.Fatal("backup failed")
	}
	out, errOut, code := env.run(t, "status", "--chain", "--json")
	if code != 0 {
		t.Fatalf("status --chain exit = %d: %s", code, errOut)
	}
	var doc struct {
		Packs struct {
			Local      int `json:"local"`
			Referenced int `json:"referenced"`
			Orphan     int `json:"orphan"`
			Missing    int `json:"missing"`
		} `json:"packs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("status --chain --json invalid: %v", err)
	}
	if doc.Packs.Local != 1 || doc.Packs.Referenced != 1 || doc.Packs.Missing != 0 || doc.Packs.Orphan != 0 {
		t.Fatalf("unexpected pack statistics: %+v", doc.Packs)
	}

	// Remove the only pack: restore must wait, then fail with E13 (13).
	packs, err := filepath.Glob(filepath.Join(env.target, "data", "*", "*.dat"))
	if err != nil || len(packs) == 0 {
		t.Fatalf("no packs found: %v", err)
	}
	if err := os.Remove(packs[0]); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, code = env.run(t, "restore", filepath.Join(env.root, "late"), "--wait-for-packs", "1s")
	elapsed := time.Since(start)
	if code != apexerr.ExitIncomplete {
		t.Fatalf("restore with a missing pack exit = %d, want %d", code, apexerr.ExitIncomplete)
	}
	if elapsed < time.Second {
		t.Fatalf("--wait-for-packs returned after %s, expected >= 1s", elapsed)
	}
}
