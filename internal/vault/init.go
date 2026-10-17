package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
)

// Calibration targets from spec 02.7.
const (
	CalibrationLowMS  = 1000 // below this we double memory
	CalibrationHighMS = 2000 // above this we fall back to the minimum
)

// Probe measures one Argon2id derivation. Production uses DeriveMasterKey;
// tests inject a fake clock to exercise the decision table quickly.
type Probe func(p vaultcrypto.KDFParams) time.Duration

// RealProbe derives a key with the real implementation.
func RealProbe(password []byte) Probe {
	return func(p vaultcrypto.KDFParams) time.Duration {
		start := time.Now()
		k, err := vaultcrypto.DeriveMasterKey(password, p)
		if err != nil {
			return 0
		}
		k.Destroy()
		return time.Since(start)
	}
}

// Calibrate implements the one-time KDF calibration of spec 02.7.
//
// Order of decisions (must not be reordered):
//  1. start at 256 MiB / t=3;
//  2. inside [1s, 2s] -> accept;
//  3. faster than 1s -> double memory until it is slow enough or hits 1 GiB;
//  4. slower than 2s -> fall back to 128 MiB and accept the slower unlock.
func Calibrate(salt []byte, threads uint8, probe Probe, now time.Time) (vaultcrypto.KDFParams, error) {
	if len(salt) != vaultcrypto.SaltLen {
		return vaultcrypto.KDFParams{}, fmt.Errorf("vault: salt must be %d bytes", vaultcrypto.SaltLen)
	}
	if threads < 1 || threads > vaultcrypto.KDFThreadsMax {
		threads = vaultcrypto.DefaultThreads()
	}
	p := vaultcrypto.KDFParams{
		Algorithm:        vaultcrypto.KDFAlgArgon2id,
		Time:             vaultcrypto.KDFTimeMin,
		MemoryKiB:        vaultcrypto.KDFMemoryKiBDefault,
		Threads:          threads,
		KeyLen:           vaultcrypto.KeyLen,
		Salt:             salt,
		CalibratedAtUnix: now.Unix(),
	}
	for {
		d := probe(p)
		ms := d.Milliseconds()
		if ms > CalibrationHighMS {
			if p.MemoryKiB > vaultcrypto.KDFMemoryKiBMin {
				p.MemoryKiB = vaultcrypto.KDFMemoryKiBMin
				p.CalibratedAtUnix = now.Unix()
				continue
			}
			return p, nil
		}
		if ms >= CalibrationLowMS {
			return p, nil
		}
		next := p.MemoryKiB * 2
		if next > vaultcrypto.KDFMemoryKiBMax {
			return p, nil
		}
		p.MemoryKiB = next
		p.CalibratedAtUnix = now.Unix()
	}
}

// Strength levels for the password check (spec 02.8 / 08.4).
const (
	StrengthWeak = iota
	StrengthModerate
	StrengthStrong
)

// Strength is the outcome of the password policy check.
type Strength struct {
	Level   int
	Reasons []string
}

// RequiresConfirmation reports whether init must demand an explicit "yes".
func (s Strength) RequiresConfirmation() bool { return s.Level == StrengthWeak }

// CheckPassword implements the init-time password policy.
//
// Spec 08.4 recommends "4 diceware words"; we do not enforce a policy that would
// lock users out of their own data, we require informed consent for weak ones.
func CheckPassword(pw []byte) Strength {
	s := Strength{Level: StrengthStrong}
	add := func(level int, reason string) {
		if level < s.Level {
			s.Level = level
		}
		s.Reasons = append(s.Reasons, reason)
	}
	str := string(pw)
	if len(pw) < 12 {
		add(StrengthWeak, "长度不足 12 字节")
	}
	if len(pw) < 16 && !strings.ContainsAny(str, "!@#$%^&*()-_=+[]{};:'\",./<>?") {
		add(StrengthModerate, "长度不足 16 且不含符号")
	}
	if allSameRune(str) && len(str) > 0 {
		add(StrengthWeak, "字符重复")
	}
	if _, hit := commonPasswords[strings.ToLower(str)]; hit {
		add(StrengthWeak, "命中常见密码清单")
	}
	if onlyDigits(str) {
		add(StrengthWeak, "纯数字")
	}
	if s.Reasons == nil {
		s.Reasons = []string{"未命中弱密码规则"}
	}
	return s
}

func allSameRune(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func onlyDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// commonPasswords is a deliberately small built-in list. The spec asks for the
// top 100k; shipping those needs a separate wordlist asset (see open-questions).
var commonPasswords = func() map[string]struct{} {
	list := []string{
		"123456", "password", "123456789", "12345678", "12345", "111111", "1234567",
		"sunshine", "qwerty", "iloveyou", "princess", "admin", "welcome", "666666",
		"abc123", "football", "123123", "monkey", "654321", "!@#$%^&*", "charlie",
		"aa123456", "donald", "password1", "qwerty123", "letmein", "trustno1",
		"passw0rd", "zaq12wsx", "master", "hello", "freedom", "whatever", "qazwsx",
		"000000", "123qwe", "killer", "jordan", "harley", "dragon", "michael",
		"superman", "batman", "starwars", "baseball", "soccer", "hockey", "ninja",
		"secret", "root", "toor", "changeme", "default", "test", "test123",
		"password123", "administrator", "p@ssw0rd", "qwertyuiop", "1q2w3e4r",
		"1qaz2wsx", "zxcvbnm", "asdfghjkl", "qwertyui", "nothing", "abcdefg",
		"aaaaaaaa", "7777777", "88888888", "999999999", "121212", "131313",
		"iloveyou1", "lovely", "whatever1", "blessing", "sunflower", "mypassword",
	}
	m := make(map[string]struct{}, len(list))
	for _, p := range list {
		m[p] = struct{}{}
	}
	return m
}()

// InitOptions drives one init run.
type InitOptions struct {
	Password    []byte
	Threads     uint8
	Now         time.Time
	Probe       Probe // nil = real Argon2id
	Force       bool  // caller already confirmed a weak password
	ToolVersion string
}

// InitResult is what the CLI needs to print after init.
type InitResult struct {
	Meta     *Meta
	Strength Strength
	Params   vaultcrypto.KDFParams
}

// Init creates a new vault.meta in dir.
func Init(dir string, opts InitOptions) (*InitResult, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	strength := CheckPassword(opts.Password)
	if strength.RequiresConfirmation() && !opts.Force {
		return nil, apexerr.New(apexerr.CodeUsage, "主密码强度不足，需要显式确认后继续").
			WithScope("原因：" + strings.Join(strength.Reasons, "；")).
			WithNext("重新设置更强的主密码，或加 --accept-weak-password 明确承担风险")
	}
	salt, err := vaultcrypto.RandomBytes(vaultcrypto.SaltLen)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法生成盐值")
	}
	probe := opts.Probe
	if probe == nil {
		probe = RealProbe(opts.Password)
	}
	params, err := Calibrate(salt, opts.Threads, probe, opts.Now)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "KDF 校准失败")
	}
	m, err := NewMeta(opts.Password, params, opts.Now)
	if err != nil {
		return nil, err
	}
	if err := m.Save(dir); err != nil {
		return nil, err
	}
	if err := WriteRecoveryNote(dir, m, params, opts.ToolVersion); err != nil {
		return nil, err
	}
	return &InitResult{Meta: m, Strength: strength, Params: params}, nil
}

// WriteRecoveryNote writes the printable RECOVERY.txt in the control plane
// (spec 07.1: never inside TargetDir).
func WriteRecoveryNote(dir string, m *Meta, params vaultcrypto.KDFParams, toolVersion string) error {
	body := recoveryTemplate(m, params, toolVersion)
	path := filepath.Join(dir, RecoveryFileName)
	if err := os.WriteFile(path, []byte(body), FilePerm); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法写入 %s", path)
	}
	return nil
}
