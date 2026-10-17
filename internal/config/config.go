// Package config loads and validates ~/.config/apex/config.toml (spec 10.3).
//
// The file never contains secrets: any password-like key is a hard error.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// Defaults fixed by spec 03.6 / 10.3.
const (
	DefaultPackMaxBytes    uint64 = 128 << 20
	DefaultSlicePlainBytes uint64 = 32 << 20
	DefaultSmallFileBytes  uint64 = 64 << 20
	DefaultSessionMaxMiB   uint64 = 256
	DefaultStagingMillis          = 0

	// EnvelopeOverhead is the fixed per-slice cost (header + tag).
	EnvelopeOverhead = 50
)

// Config is the full configuration tree.
type Config struct {
	Vault      VaultConfig      `toml:"vault"`
	Storage    StorageConfig    `toml:"storage"`
	Codec      CodecConfig      `toml:"codec"`
	Scan       ScanConfig       `toml:"scan"`
	OnChange   ChangeConfig     `toml:"on_change_during_read"`
	Workers    Concurrency      `toml:"concurrency"`
	Checkpoint CheckpointConfig `toml:"checkpoint"`
	Verify     VerifyConfig     `toml:"verify"`
}

// VaultConfig is the control plane location.
type VaultConfig struct {
	Dir string `toml:"dir"`
}

// StorageConfig is the TargetDir parameters.
type StorageConfig struct {
	TargetDir       string `toml:"target_dir"`
	StagingDir      string `toml:"staging_dir"`
	PackMaxBytes    uint64 `toml:"pack_max_bytes"`
	SlicePlainBytes uint64 `toml:"slice_plain_bytes"`
	SmallFileBytes  uint64 `toml:"small_file_bytes"`
	SessionMaxMiB   uint64 `toml:"session_max_mib"`
}

// CodecConfig controls compression.
type CodecConfig struct {
	ZstdLevel        int `toml:"zstd_level"`
	MinCompressBytes int `toml:"min_compress_bytes"`
}

// ScanConfig controls the source scan.
type ScanConfig struct {
	Mode            string   `toml:"mode"`
	Exclude         []string `toml:"exclude"`
	FollowHardlinks string   `toml:"follow_hardlinks"`
	IgnoreXattr     bool     `toml:"ignore_xattr"`
	SparseMaxBytes  int64    `toml:"sparse_max_bytes"`
}

// ChangeConfig is the read-time consistency strategy (spec 05.4).
type ChangeConfig struct {
	Strategy string `toml:"strategy"`
}

// Concurrency bounds.
type Concurrency struct {
	Hashers     int `toml:"hashers"`
	PackWriters int `toml:"pack_writers"`
}

// CheckpointConfig controls checkpoint generation.
type CheckpointConfig struct {
	EveryCommits int `toml:"every_commits"`
	MaxAgeDays   int `toml:"max_age_days"`
}

// VerifyConfig controls automatic strict scans.
type VerifyConfig struct {
	AutoStrictEvery int `toml:"auto_strict_every"`
}

// Default returns the documented defaults.
func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Vault: VaultConfig{Dir: filepath.Join(home, ".config", "apex-vault")},
		Storage: StorageConfig{
			PackMaxBytes:    DefaultPackMaxBytes,
			SlicePlainBytes: DefaultSlicePlainBytes,
			SmallFileBytes:  DefaultSmallFileBytes,
			SessionMaxMiB:   DefaultSessionMaxMiB,
		},
		Codec: CodecConfig{ZstdLevel: 5, MinCompressBytes: 4096},
		Scan: ScanConfig{
			Mode:            "fast",
			Exclude:         []string{".git/**", "node_modules/**", "*.tmp", ".DS_Store"},
			FollowHardlinks: "error",
			SparseMaxBytes:  0,
		},
		OnChange:   ChangeConfig{Strategy: "retry"},
		Workers:    Concurrency{Hashers: 4, PackWriters: 2},
		Checkpoint: CheckpointConfig{EveryCommits: 256, MaxAgeDays: 30},
		Verify:     VerifyConfig{AutoStrictEvery: 30},
	}
}

// DefaultPath is ~/.config/apex/config.toml.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.toml"
	}
	return filepath.Join(home, ".config", "apex", "config.toml")
}

// Load reads path on top of the defaults. A missing file is not an error.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, cfg.Validate()
		}
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法读取配置文件：%s", path)
	}
	if info, serr := os.Stat(path); serr == nil {
		if info.Mode().Perm()&0o077 != 0 {
			return nil, apexerr.Newf(apexerr.CodeUsage,
				"配置文件权限过宽：%s（%o），其他用户可能读到目标路径", path, info.Mode().Perm()).
				WithNext("执行 chmod 600 " + path)
		}
	}
	if err := rejectSecrets(raw); err != nil {
		return nil, err
	}
	if err := toml.Unmarshal(raw, cfg); err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "配置文件语法错误：%s", path)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectSecrets enforces spec 10.3: no password material in the config file.
func rejectSecrets(raw []byte) error {
	var tree map[string]any
	if err := toml.Unmarshal(raw, &tree); err != nil {
		// Syntax errors are reported by Load afterwards.
		return nil
	}
	var walk func(prefix string, m map[string]any) error
	walk = func(prefix string, m map[string]any) error {
		for k, v := range m {
			lower := strings.ToLower(k)
			for _, bad := range []string{"password", "passphrase", "secret", "master_key"} {
				if strings.Contains(lower, bad) {
					return apexerr.Newf(apexerr.CodeUsage, "配置文件不允许出现密钥字段：%s%s", prefix, k).
						WithScope("这会把主密码写进磁盘与同步目录").
						WithNext("删除该字段，改用 --password-fd 或交互式输入")
				}
			}
			if sub, ok := v.(map[string]any); ok {
				if err := walk(prefix+k+".", sub); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk("", tree)
}

// Validate enforces the cross-parameter rules of spec 03.6.
func (c *Config) Validate() error {
	if c.Storage.SlicePlainBytes == 0 || c.Storage.SmallFileBytes == 0 || c.Storage.PackMaxBytes == 0 {
		return apexerr.New(apexerr.CodeUsage, "storage 参数不能为 0")
	}
	if c.Storage.SlicePlainBytes > wire.MaxSlicePlainHard {
		return apexerr.Newf(apexerr.CodeUsage,
			"storage.slice_plain_bytes=%d 超过线格式上限 %d", c.Storage.SlicePlainBytes, wire.MaxSlicePlainHard)
	}
	if c.Storage.SlicePlainBytes+EnvelopeOverhead > c.Storage.PackMaxBytes {
		return apexerr.Newf(apexerr.CodeUsage,
			"slice_plain_bytes(%d)+%d 超过 pack_max_bytes(%d)，会在运行中退化",
			c.Storage.SlicePlainBytes, EnvelopeOverhead, c.Storage.PackMaxBytes).
			WithNext("调大 pack_max_bytes 或调小 slice_plain_bytes")
	}
	if c.Storage.SmallFileBytes+EnvelopeOverhead > c.Storage.PackMaxBytes {
		return apexerr.Newf(apexerr.CodeUsage,
			"small_file_bytes(%d)+%d 超过 pack_max_bytes(%d)：64 MiB 文件永远塞不进新 pack",
			c.Storage.SmallFileBytes, EnvelopeOverhead, c.Storage.PackMaxBytes)
	}
	switch c.Scan.Mode {
	case "fast", "strict":
	default:
		return apexerr.Newf(apexerr.CodeUsage, "scan.mode=%q 非法（fast|strict）", c.Scan.Mode)
	}
	switch c.OnChange.Strategy {
	case "retry", "skip", "fail":
	default:
		return apexerr.Newf(apexerr.CodeUsage, "on_change_during_read.strategy=%q 非法（retry|skip|fail）", c.OnChange.Strategy)
	}
	switch c.Scan.FollowHardlinks {
	case "error", "split":
	default:
		return apexerr.Newf(apexerr.CodeUsage, "scan.follow_hardlinks=%q 非法（error|split）", c.Scan.FollowHardlinks)
	}
	if c.Workers.PackWriters < 1 {
		return apexerr.New(apexerr.CodeUsage, "concurrency.pack_writers 必须 >= 1")
	}
	if c.Storage.SessionMaxMiB == 0 {
		return apexerr.New(apexerr.CodeUsage, "storage.session_max_mib 必须 > 0")
	}
	return nil
}

// Params returns the journal parameter snapshot for this config.
func (c *Config) Params() wire.VaultParams {
	return wire.VaultParams{
		SlicePlainBytes: c.Storage.SlicePlainBytes,
		SmallFileBytes:  c.Storage.SmallFileBytes,
		PackMaxBytes:    c.Storage.PackMaxBytes,
		SessionMaxMiB:   c.Storage.SessionMaxMiB,
	}
}

// String renders a short human description for logs.
func (c *Config) String() string {
	return fmt.Sprintf("target=%s slice=%dMiB pack=%dMiB", c.Storage.TargetDir,
		c.Storage.SlicePlainBytes>>20, c.Storage.PackMaxBytes>>20)
}
