package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultsValidate(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if cfg.Storage.PackMaxBytes != DefaultPackMaxBytes || cfg.Storage.SlicePlainBytes != DefaultSlicePlainBytes {
		t.Fatalf("unexpected defaults: %+v", cfg.Storage)
	}
}

func TestLoadOverrides(t *testing.T) {
	path := writeConfig(t, `[storage]
target_dir = "/tmp/target"
slice_plain_bytes = 16777216

[scan]
mode = "strict"
exclude = ["*.log"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.TargetDir != "/tmp/target" || cfg.Storage.SlicePlainBytes != 16<<20 {
		t.Fatalf("overrides not applied: %+v", cfg.Storage)
	}
	if cfg.Scan.Mode != "strict" || len(cfg.Scan.Exclude) != 1 || cfg.Scan.Exclude[0] != "*.log" {
		t.Fatalf("scan overrides not applied: %+v", cfg.Scan)
	}
	if cfg.Storage.PackMaxBytes != DefaultPackMaxBytes {
		t.Fatalf("untouched defaults lost: %+v", cfg.Storage)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.SlicePlainBytes != DefaultSlicePlainBytes {
		t.Fatal("defaults not returned")
	}
}

func TestRejectSecrets(t *testing.T) {
	path := writeConfig(t, `[storage]
target_dir = "/tmp/target"

[vault]
password = "hunter2"
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected a password field to be rejected")
	} else if apexerr.CodeOf(err) != apexerr.CodeUsage {
		t.Fatalf("code = %s", apexerr.CodeOf(err))
	}
}

func TestRejectLoosePermissions(t *testing.T) {
	path := writeConfig(t, `[storage]
target_dir = "/tmp/x"
`)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected 0644 config to be rejected")
	}
}

func TestValidationRules(t *testing.T) {
	cases := map[string]func(*Config){
		"slice larger than pack": func(c *Config) { c.Storage.SlicePlainBytes = 256 << 20 },
		"small file larger than pack": func(c *Config) {
			c.Storage.SmallFileBytes = 200 << 20
		},
		"slice above wire ceiling": func(c *Config) {
			c.Storage.SlicePlainBytes = wire.MaxSlicePlainHard + 1
			c.Storage.PackMaxBytes = 1 << 30
		},
		"bad scan mode":       func(c *Config) { c.Scan.Mode = "ultra" },
		"bad change strategy": func(c *Config) { c.OnChange.Strategy = "ignore" },
		"bad hardlink mode":   func(c *Config) { c.Scan.FollowHardlinks = "follow" },
		"zero writers":        func(c *Config) { c.Workers.PackWriters = 0 },
		"zero session":        func(c *Config) { c.Storage.SessionMaxMiB = 0 },
	}
	for name, mutate := range cases {
		cfg := Default()
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParamsSnapshot(t *testing.T) {
	cfg := Default()
	p := cfg.Params()
	if p.SlicePlainBytes != cfg.Storage.SlicePlainBytes || p.PackMaxBytes != cfg.Storage.PackMaxBytes {
		t.Fatalf("params mismatch: %+v", p)
	}
	if !strings.Contains(cfg.String(), "target=") {
		t.Fatalf("String() = %q", cfg.String())
	}
}
