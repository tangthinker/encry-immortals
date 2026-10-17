// Package armor implements the Armor Key encoding of spec §02.10 / D-16.
//
//	EIMMORTAL-KEY-V2-<payload>
//	payload = Crockford-Base32( zstd(vault.meta JSON) || CRC32C(zstd bytes) )
//
// Design goals: hand-copyable (no ambiguous letters, grouped, CRC-checked),
// searchable in a password manager (stable prefix) and unambiguous on import
// (CRC before decompression, decompression size-capped).
package armor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

const (
	// Prefix identifies the format version and makes the string searchable.
	Prefix = "EIMMORTAL-KEY-V2-"
	// GroupSize is the human-facing grouping width (spec §07.3).
	GroupSize = 5
	// LineWidth is the print width for the grouped form.
	LineWidth = 72
	// MaxMetaBytes caps the decompressed vault.meta size (bomb protection).
	MaxMetaBytes = 1 << 20
)

// LegacyPrefixes are still accepted on import so that keys exported before the
// rename keep working. New exports always use Prefix.
var LegacyPrefixes = []string{"APEX-KEY-V2-"}

// Crockford Base32 alphabet: no I, L, O, U.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var encPool = sync.Pool{
	New: func() any {
		w, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		if err != nil {
			panic("armor: zstd encoder: " + err.Error())
		}
		return w
	},
}

// Encode renders payload as unpadded Crockford Base32 (no prefix, no grouping).
func Encode(payload []byte) string {
	var b strings.Builder
	b.Grow((len(payload)*8 + 4) / 5)
	var chunk [5]byte
	for i := 0; i < len(payload); i += 5 {
		n := len(payload) - i
		if n > 5 {
			n = 5
		}
		chunk = [5]byte{}
		copy(chunk[:], payload[i:i+n])

		var v uint64
		for j := 0; j < 5; j++ {
			v = v<<8 | uint64(chunk[j])
		}
		chars := (n*8 + 4) / 5
		for j := 0; j < chars; j++ {
			b.WriteByte(alphabet[(v>>(35-uint(j)*5))&0x1f])
		}
	}
	return b.String()
}

// Decode parses unpadded Crockford Base32. It ignores hyphens and whitespace,
// accepts lower case and maps the ambiguous letters I/L to 1 and O to 0.
func Decode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*5/8+1)
	var bits uint64
	var nbits uint
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t', '\r', '\n':
			continue
		}
		v, ok := decodeChar(byte(r))
		if !ok {
			return nil, fmt.Errorf("非法字符 %q", r)
		}
		bits = bits<<5 | uint64(v)
		nbits += 5
		if nbits >= 8 {
			nbits -= 8
			out = append(out, byte(bits>>nbits))
			bits &= (1 << nbits) - 1
		}
	}
	if bits != 0 {
		return nil, fmt.Errorf("尾部填充位非零")
	}
	return out, nil
}

func decodeChar(c byte) (byte, bool) {
	switch c {
	case 'I', 'L':
		c = '1'
	case 'O':
		c = '0'
	}
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == c {
			return byte(i), true
		}
	}
	return 0, false
}

// Seal compresses, checksums and renders vault.meta JSON as an Armor Key.
func Seal(metaJSON []byte) (string, error) {
	if len(metaJSON) == 0 {
		return "", apexerr.New(apexerr.CodeArmor, "无法生成 Armor Key：vault.meta 内容为空")
	}
	enc := encPool.Get().(*zstd.Encoder)
	body := enc.EncodeAll(metaJSON, nil)
	encPool.Put(enc)

	payload := make([]byte, 0, len(body)+4)
	payload = append(payload, body...)
	payload = binary.BigEndian.AppendUint32(payload, crc32.Checksum(body, castagnoli))
	return Prefix + Encode(payload), nil
}

// Open validates and decodes an Armor Key back to vault.meta JSON.
//
// Order is fixed by spec §02.10: prefix -> base32 -> CRC -> decompress -> caller
// parses JSON. Any failure is E16 so that "user mistyped" and "wrong vault" are
// indistinguishable from the outside.
func Open(encoded string) ([]byte, error) {
	s := strings.TrimSpace(encoded)
	payloadStr, ok := trimAnyPrefix(s)
	if !ok {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 无法识别：缺少 "+Prefix+" 前缀").
			WithNext("确认粘贴完整，或重新执行 eimmortal export-key")
	}
	payload, err := Decode(payloadStr)
	if err != nil {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 无法解码").
			WithErr(err).
			WithNext("逐字符核对 Armor Key，注意每 5 个字符一组")
	}
	if len(payload) < 5 {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 长度不足")
	}
	body := payload[:len(payload)-4]
	want := binary.BigEndian.Uint32(payload[len(payload)-4:])
	if got := crc32.Checksum(body, castagnoli); got != want {
		return nil, apexerr.Newf(apexerr.CodeArmor, "Armor 字符串损坏（CRC 校验失败：期望 %08x，实际 %08x）", want, got).
			WithNext("重新抄写或重新执行 eimmortal export-key")
	}
	r, err := zstd.NewReader(bytes.NewReader(body),
		zstd.WithDecoderMaxMemory(MaxMetaBytes),
		zstd.WithDecoderMaxWindow(MaxMetaBytes),
		zstd.WithDecoderConcurrency(1),
	)
	if err != nil {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 压缩数据损坏").WithErr(err)
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, MaxMetaBytes+1))
	if err != nil {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 压缩数据损坏").WithErr(err)
	}
	if len(out) > MaxMetaBytes {
		return nil, apexerr.New(apexerr.CodeArmor, "Armor Key 解压后超过大小上限")
	}
	return out, nil
}

// FormatSingle is the one-line form for password managers.
func FormatSingle(encoded string) string { return encoded }

// trimAnyPrefix strips the current or a legacy prefix (case-insensitive).
func trimAnyPrefix(s string) (string, bool) {
	for _, p := range append([]string{Prefix}, LegacyPrefixes...) {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			return s[len(p):], true
		}
	}
	return "", false
}

// FormatGrouped is the hand-copy form: groups of GroupSize characters separated
// by hyphens, wrapped at LineWidth columns.
func FormatGrouped(encoded string) string {
	payload, _ := trimAnyPrefix(encoded)
	var groups []string
	for i := 0; i < len(payload); i += GroupSize {
		end := i + GroupSize
		if end > len(payload) {
			end = len(payload)
		}
		groups = append(groups, payload[i:end])
	}
	var lines []string
	line := Prefix
	for i, g := range groups {
		sep := ""
		if i > 0 {
			sep = "-"
		}
		if len(line)+len(sep)+len(g) > LineWidth {
			lines = append(lines, line)
			line = ""
			sep = ""
		}
		line += sep + g
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
