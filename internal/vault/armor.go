package vault

import (
	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/armor"
)

// Armor renders this vault.meta as an Armor Key (spec 02.10 / D-16).
func (m *Meta) Armor() (string, error) {
	raw, err := m.Marshal()
	if err != nil {
		return "", err
	}
	s, err := armor.Seal(raw)
	if err != nil {
		return "", err
	}
	return s, nil
}

// ParseArmorString validates an Armor Key and returns the embedded vault.meta.
//
// Order is CRC -> decompress -> JSON -> version -> field validation; any failure
// is E16 so the operator sees a single actionable message.
func ParseArmorString(s string) (*Meta, error) {
	raw, err := armor.Open(s)
	if err != nil {
		return nil, err
	}
	m, err := ParseMeta(raw)
	if err != nil {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 内容不是合法的 vault.meta").
			WithErr(err).
			WithNext("确认使用的是本 vault 的 Armor Key，且工具版本不落后于数据格式")
	}
	return m, nil
}
