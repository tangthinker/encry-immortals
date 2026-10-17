// Package vault owns the control plane: vault.meta, key unlocking, calibration,
// password policy and the Armor Key (spec 01, 02, 07).
package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/store"
)

// Control-plane file and directory names (spec 01.1).
const (
	MetaVersion      = 2
	MetaFileName     = "vault.meta"
	StateFileName    = "state.db"
	RecoveryFileName = "RECOVERY.txt"
	// DirPerm / FilePerm keep the control plane private.
	DirPerm  os.FileMode = 0o700
	FilePerm os.FileMode = 0o600
)

// Meta is the v2 vault.meta contract (spec 02.3). Fields are strings so the
// Base64URL alphabet is explicit and cannot drift with encoding/json.
type Meta struct {
	Version      int          `json:"version"`
	VaultID      string       `json:"vault_id"`
	CreatedUnix  int64        `json:"created_unix"`
	KDF          KDFJSON      `json:"kdf"`
	AuthVerifier VerifierJSON `json:"auth_verifier"`
}

// KDFJSON mirrors vaultcrypto.KDFParams on the wire.
type KDFJSON struct {
	Algorithm        string `json:"algorithm"`
	Time             uint32 `json:"time"`
	MemoryKiB        uint32 `json:"memory_kiB"`
	Threads          uint8  `json:"threads"`
	KeyLen           uint32 `json:"keylen"`
	Salt             string `json:"salt"`
	CalibratedAtUnix int64  `json:"calibrated_at_unix"`
}

// VerifierJSON is the password check point (spec 02.4).
type VerifierJSON struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Keys is an unlocked key set. Callers must Destroy it.
type Keys struct {
	Master  *vaultcrypto.SecureKey
	Sub     *vaultcrypto.Subkeys
	VaultID [16]byte
}

// Destroy wipes every key.
func (k *Keys) Destroy() {
	if k == nil {
		return
	}
	k.Sub.Destroy()
	k.Master.Destroy()
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s, what string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s 不是合法的 Base64URL: %w", what, err)
	}
	return b, nil
}

// KDFParams decodes and validates the frozen KDF parameters.
func (m *Meta) KDFParams() (vaultcrypto.KDFParams, error) {
	var p vaultcrypto.KDFParams
	if m == nil {
		return p, fmt.Errorf("vault.meta 为空")
	}
	salt, err := unb64(m.KDF.Salt, "kdf.salt")
	if err != nil {
		return p, err
	}
	p = vaultcrypto.KDFParams{
		Algorithm:        m.KDF.Algorithm,
		Time:             m.KDF.Time,
		MemoryKiB:        m.KDF.MemoryKiB,
		Threads:          m.KDF.Threads,
		KeyLen:           m.KDF.KeyLen,
		Salt:             salt,
		CalibratedAtUnix: m.KDF.CalibratedAtUnix,
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

// VaultIDBytes decodes the vault identity.
func (m *Meta) VaultIDBytes() ([]byte, error) {
	id, err := unb64(m.VaultID, "vault_id")
	if err != nil {
		return nil, err
	}
	if len(id) != vaultcrypto.VaultIDLen {
		return nil, fmt.Errorf("vault_id 长度 %d，期望 %d", len(id), vaultcrypto.VaultIDLen)
	}
	return id, nil
}

// CanonKDF returns the canonical KDF block hashed into the verifier AAD.
func (m *Meta) CanonKDF() (string, error) {
	p, err := m.KDFParams()
	if err != nil {
		return "", err
	}
	return p.CanonBlock(), nil
}

// NewMeta builds a fresh vault.meta and the matching auth_verifier.
//
// The caller supplies already-calibrated parameters: calibration happens once,
// in init, and is then frozen forever (I19).
func NewMeta(password []byte, params vaultcrypto.KDFParams, now time.Time) (*Meta, error) {
	if err := params.Validate(); err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeUsage, "KDF 参数非法")
	}
	if len(password) == 0 {
		return nil, apexerr.New(apexerr.CodeUsage, "主密码不能为空")
	}
	vaultID, err := vaultcrypto.RandomBytes(vaultcrypto.VaultIDLen)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法生成 vault_id")
	}
	master, err := vaultcrypto.DeriveMasterKey(password, params)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法派生主密钥")
	}
	defer master.Destroy()
	sub, err := vaultcrypto.DeriveSubkeys(master.Bytes(), vaultID)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法派生子密钥")
	}
	defer sub.Destroy()
	nonce, ct, err := vaultcrypto.SealAuthVerifier(sub.Journal.Bytes(), vaultID, params.CanonBlock())
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法生成 auth_verifier")
	}
	return &Meta{
		Version:     MetaVersion,
		VaultID:     b64(vaultID),
		CreatedUnix: now.Unix(),
		KDF: KDFJSON{
			Algorithm:        params.Algorithm,
			Time:             params.Time,
			MemoryKiB:        params.MemoryKiB,
			Threads:          params.Threads,
			KeyLen:           params.KeyLen,
			Salt:             b64(params.Salt),
			CalibratedAtUnix: params.CalibratedAtUnix,
		},
		AuthVerifier: VerifierJSON{
			Algorithm:  "xchacha20poly1305",
			Nonce:      b64(nonce),
			Ciphertext: b64(ct),
		},
	}, nil
}

// Marshal renders the canonical file representation.
func (m *Meta) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法序列化 vault.meta")
	}
	return append(raw, '\n'), nil
}

// ParseMeta validates a vault.meta document.
func ParseMeta(raw []byte) (*Meta, error) {
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("vault.meta 不是合法 JSON: %w", err)
	}
	if m.Version != MetaVersion {
		return nil, fmt.Errorf("vault.meta 版本 %d 不受支持（当前 %d）", m.Version, MetaVersion)
	}
	if _, err := m.KDFParams(); err != nil {
		return nil, err
	}
	if _, err := m.VaultIDBytes(); err != nil {
		return nil, err
	}
	if m.AuthVerifier.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("auth_verifier 算法 %q 不受支持", m.AuthVerifier.Algorithm)
	}
	nonce, err := unb64(m.AuthVerifier.Nonce, "auth_verifier.nonce")
	if err != nil || len(nonce) != vaultcrypto.NonceLen {
		return nil, fmt.Errorf("auth_verifier.nonce 非法")
	}
	ct, err := unb64(m.AuthVerifier.Ciphertext, "auth_verifier.ciphertext")
	if err != nil || len(ct) != len(vaultcrypto.VerifierPlaintext)+vaultcrypto.TagLen {
		return nil, fmt.Errorf("auth_verifier.ciphertext 非法")
	}
	return &m, nil
}

// LoadMeta reads <dir>/vault.meta.
func LoadMeta(dir string) (*Meta, error) {
	path := filepath.Join(dir, MetaFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apexerr.Newf(apexerr.CodeUsage, "vault 未初始化：找不到 %s", path).
				WithNext("先执行 eimmortal init，或执行 eimmortal init --join <TargetDir> 后 import-key")
		}
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法读取 %s", path)
	}
	m, err := ParseMeta(raw)
	if err != nil {
		return nil, apexerr.New(apexerr.CodeUnlock, "无法解封 vault.meta：密码错误，或 vault.meta 已损坏").
			WithScope("vault.meta 结构非法（" + err.Error() + "）").
			WithNext("若刚更换过机器，请用 eimmortal import-key 重新导入 Armor Key")
	}
	return m, nil
}

// Save writes vault.meta atomically with 0600 permissions.
func (m *Meta) Save(dir string) error {
	if err := os.MkdirAll(dir, DirPerm); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建控制平面目录：%s", dir)
	}
	if err := os.Chmod(dir, DirPerm); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeInternal, "无法设置控制平面目录权限：%s", dir)
	}
	raw, err := m.Marshal()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, MetaFileName)
	tmp, err := os.CreateTemp(dir, ".vault.meta.*")
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建临时文件")
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return apexerr.Wrap(err, apexerr.CodeNoSpace, "写入 vault.meta 失败")
	}
	if err := tmp.Chmod(FilePerm); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return apexerr.Wrap(err, apexerr.CodeInternal, "设置 vault.meta 权限失败")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return apexerr.Wrap(err, apexerr.CodeNoSpace, "刷盘 vault.meta 失败")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return apexerr.Wrap(err, apexerr.CodeNoSpace, "关闭 vault.meta 失败")
	}
	if err := store.RenameDurable(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// Unlock derives the full key set and verifies the password.
//
// Every failure is reported as E10 with one fixed message: spec 02.9 forbids
// distinguishing "wrong password" from "corrupt vault.meta" (I20).
func (m *Meta) Unlock(password []byte) (*Keys, error) {
	keys, err := m.unlock(password)
	if err != nil {
		return nil, apexerr.New(apexerr.CodeUnlock, "无法解封 vault.meta：密码错误，或 vault.meta 已损坏").
			WithNext("确认密码后重试；若刚更换过机器，请用 eimmortal import-key 重新导入 Armor Key")
	}
	return keys, nil
}

func (m *Meta) unlock(password []byte) (*Keys, error) {
	params, err := m.KDFParams()
	if err != nil {
		return nil, err
	}
	vaultID, err := m.VaultIDBytes()
	if err != nil {
		return nil, err
	}
	master, err := vaultcrypto.DeriveMasterKey(password, params)
	if err != nil {
		return nil, err
	}
	sub, err := vaultcrypto.DeriveSubkeys(master.Bytes(), vaultID)
	if err != nil {
		master.Destroy()
		return nil, err
	}
	nonce, err := unb64(m.AuthVerifier.Nonce, "nonce")
	if err != nil {
		sub.Destroy()
		master.Destroy()
		return nil, err
	}
	ct, err := unb64(m.AuthVerifier.Ciphertext, "ciphertext")
	if err != nil {
		sub.Destroy()
		master.Destroy()
		return nil, err
	}
	if err := vaultcrypto.OpenAuthVerifier(sub.Journal.Bytes(), nonce, ct, vaultID, params.CanonBlock()); err != nil {
		sub.Destroy()
		master.Destroy()
		return nil, err
	}
	k := &Keys{Master: master, Sub: sub}
	copy(k.VaultID[:], vaultID)
	return k, nil
}
