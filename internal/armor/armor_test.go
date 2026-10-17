package armor

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// reference encoding: stdlib base32 with the Crockford alphabet, no padding.
var refBase32 = base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)

func TestEncodeMatchesReferenceBase32(t *testing.T) {
	for size := 0; size <= 67; size++ {
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		got := Encode(buf)
		want := refBase32.EncodeToString(buf)
		if got != want {
			t.Fatalf("size %d: Encode = %q, want %q", size, got, want)
		}
		back, err := Decode(got)
		if err != nil {
			t.Fatalf("size %d: Decode: %v", size, err)
		}
		if !bytes.Equal(back, buf) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestDecodeToleratesHumanNoise(t *testing.T) {
	payload := []byte("crockford base32 payload 0123456789")
	canon := Encode(payload)
	noisy := strings.ToLower(strings.Join(splitN(canon, 5), "-")) + "\n"
	back, err := Decode(noisy)
	if err != nil {
		t.Fatalf("Decode(noisy): %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("noisy decode mismatch")
	}
	// I/L -> 1 and O -> 0 are accepted aliases.
	withAliases := strings.NewReplacer("0", "O", "1", "I").Replace(canon)
	back, err = Decode(withAliases)
	if err != nil {
		t.Fatalf("Decode(aliases): %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("alias decode mismatch")
	}
	if _, err := Decode("U"); err == nil {
		t.Fatal("expected an error for the excluded letter U")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	meta := []byte(`{"version":2,"vault_id":"AAAA","kdf":{"algorithm":"argon2id"}}`)
	enc, err := Seal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, Prefix) {
		t.Fatalf("missing prefix: %q", enc)
	}
	back, err := Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, meta) {
		t.Fatal("round trip mismatch")
	}
	// The grouped form must decode identically after whitespace removal.
	grouped := FormatGrouped(enc)
	for _, line := range strings.Split(grouped, "\n") {
		if len(line) > LineWidth {
			t.Fatalf("line exceeds %d columns: %q", LineWidth, line)
		}
	}
	back, err = Open(grouped)
	if err != nil {
		t.Fatalf("Open(grouped): %v", err)
	}
	if !bytes.Equal(back, meta) {
		t.Fatal("grouped round trip mismatch")
	}
}

func TestOpenRejectsCorruption(t *testing.T) {
	enc, err := Seal([]byte(`{"version":2,"vault_id":"AAAA"}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing prefix": strings.TrimPrefix(enc, Prefix),
		"truncated":      enc[:len(enc)-6],
		"flipped char":   flipLastPayloadChar(enc),
		"illegal char":   enc[:len(enc)-1] + "U",
	}
	for name, in := range cases {
		if _, err := Open(in); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if apexerr.CodeOf(err) != apexerr.CodeArmor {
			t.Errorf("%s: code = %s, want %s", name, apexerr.CodeOf(err), apexerr.CodeArmor)
		}
	}
}

func TestGoldenArmorVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "gv4_armor.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var gv struct {
		Vectors []struct {
			PayloadHex string `json:"payload_hex"`
			Encoded    string `json:"encoded"`
		} `json:"vectors"`
		CorruptCases []struct {
			Input    string `json:"input"`
			Rejected bool   `json:"must_be_rejected"`
		} `json:"corrupt_cases"`
	}
	if err := json.Unmarshal(raw, &gv); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(gv.Vectors) < 5 {
		t.Fatalf("golden needs at least 5 vectors, got %d", len(gv.Vectors))
	}
	for i, v := range gv.Vectors {
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatalf("vector %d: bad hex: %v", i, err)
		}
		if got := Encode(payload); got != v.Encoded {
			t.Fatalf("vector %d: Encode = %q, want %q", i, got, v.Encoded)
		}
		back, err := Decode(v.Encoded)
		if err != nil {
			t.Fatalf("vector %d: Decode: %v", i, err)
		}
		if !reflect.DeepEqual(back, payload) {
			t.Fatalf("vector %d: Decode mismatch", i)
		}
	}
	for i, c := range gv.CorruptCases {
		if !c.Rejected {
			continue
		}
		if _, err := Decode(c.Input); err == nil {
			t.Fatalf("corrupt case %d was accepted: %q", i, c.Input)
		}
	}
}

func splitN(s string, n int) []string {
	var out []string
	for len(s) > 0 {
		k := n
		if k > len(s) {
			k = len(s)
		}
		out = append(out, s[:k])
		s = s[k:]
	}
	return out
}

func flipLastPayloadChar(s string) string {
	if len(s) == 0 {
		return s
	}
	last := s[len(s)-1]
	repl := byte('0')
	if last == '0' {
		repl = '1'
	}
	return s[:len(s)-1] + string(repl)
}
func TestOpenAcceptsLegacyPrefix(t *testing.T) {
	meta := []byte(`{"version":2,"vault_id":"AAAA"}`)
	enc, err := Seal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, Prefix) {
		t.Fatalf("new exports must use %s, got %q", Prefix, enc[:16])
	}
	// Keys exported before the rename keep working.
	legacy := "APEX-KEY-V2-" + strings.TrimPrefix(enc, Prefix)
	back, err := Open(legacy)
	if err != nil {
		t.Fatalf("legacy prefix rejected: %v", err)
	}
	if !bytes.Equal(back, meta) {
		t.Fatal("legacy prefix round trip mismatch")
	}
	if grouped := FormatGrouped(legacy); !strings.HasPrefix(grouped, Prefix) {
		t.Fatalf("grouped legacy key must be re-rendered with the new prefix: %q", grouped[:20])
	}
}
