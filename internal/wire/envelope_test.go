package wire

import (
	"bytes"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/codec"
)

func sampleIDs() (key, packID, txnID []byte) {
	return bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 16), bytes.Repeat([]byte{0x33}, 16)
}

func TestSliceEnvelopeRoundTrip(t *testing.T) {
	key, packID, txnID := sampleIDs()
	plain := bytes.Repeat([]byte("eimmortal slice payload "), 1000)
	codecID, payload, err := codec.Compress(plain)
	if err != nil {
		t.Fatal(err)
	}
	if codecID != codec.Zstd {
		t.Fatalf("expected compressible payload to use zstd, got %d", codecID)
	}
	env, err := SealSlice(key, codecID, len(plain), payload, packID, 32, 0, txnID)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseSliceHeader(env)
	if err != nil {
		t.Fatal(err)
	}
	if int(h.EnvLen) != len(env) || int(h.PlainLen) != len(plain) || h.Codec != codecID {
		t.Fatalf("header mismatch: %+v (env %d, plain %d)", h, len(env), len(plain))
	}
	got, cid, plen, err := OpenSlice(key, env, packID, 32, 0, txnID)
	if err != nil {
		t.Fatal(err)
	}
	if cid != codecID || plen != len(plain) {
		t.Fatalf("codec/plain_len mismatch: %d/%d", cid, plen)
	}
	back, err := codec.Decompress(cid, got, plen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatal("round trip mismatch")
	}
}

func TestSliceEnvelopeRejectsTampering(t *testing.T) {
	key, packID, txnID := sampleIDs()
	plain := bytes.Repeat([]byte("x"), 100)
	env, err := SealSlice(key, codec.None, len(plain), plain, packID, 32, 0, txnID)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(in []byte, at int) []byte {
		out := append([]byte(nil), in...)
		out[at] ^= 0x01
		return out
	}
	alternateKey := append([]byte(nil), key...)
	alternateKey[0] ^= 0xff
	alternatePack := append([]byte(nil), packID...)
	alternatePack[0] ^= 0xff
	alternateTxn := append([]byte(nil), txnID...)
	alternateTxn[0] ^= 0xff

	cases := []struct {
		name string
		key  []byte
		env  []byte
		pack []byte
		off  uint64
		idx  uint32
		txn  []byte
	}{
		{"ciphertext bit flip", key, flip(env, EnvelopeHeaderSize), packID, 32, 0, txnID},
		{"nonce bit flip", key, flip(env, 10), packID, 32, 0, txnID},
		{"tag bit flip", key, flip(env, len(env)-1), packID, 32, 0, txnID},
		{"truncated", key, env[:len(env)-1], packID, 32, 0, txnID},
		{"wrong key", alternateKey, env, packID, 32, 0, txnID},
		{"wrong pack_id", key, env, alternatePack, 32, 0, txnID},
		{"wrong offset", key, env, packID, 33, 0, txnID},
		{"wrong index", key, env, packID, 32, 1, txnID},
		{"wrong txn_id", key, env, packID, 32, 0, alternateTxn},
		{"declared env_len", key, flip(env, 4), packID, 32, 0, txnID},
		{"altered plain_len", key, flip(env, 8), packID, 32, 0, txnID},
		{"altered codec", key, flip(env, 9), packID, 32, 0, txnID},
		{"altered ver_alg", key, flip(env, 0), packID, 32, 0, txnID},
	}
	for _, c := range cases {
		if _, _, _, err := OpenSlice(c.key, c.env, c.pack, c.off, c.idx, c.txn); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

func TestSliceHeaderRejectsBadDeclaredLengths(t *testing.T) {
	env := make([]byte, EnvelopeMinLen+16)
	env[0] = 0x11
	env[1], env[2], env[3], env[4] = 0, 0, 0, byte(len(env))
	// plain_len = MaxSlicePlainHard + 1
	tooBig := uint32(MaxSlicePlainHard + 1)
	env[5], env[6], env[7], env[8] = byte(tooBig>>24), byte(tooBig>>16), byte(tooBig>>8), byte(tooBig)
	env[9] = codec.None
	if _, err := ParseSliceHeader(env); err == nil {
		t.Fatal("expected plain_len above the hard ceiling to be rejected before decryption")
	}
	env[9] = 9
	env[5], env[6], env[7], env[8] = 0, 0, 0, 0
	if _, err := ParseSliceHeader(env); err == nil {
		t.Fatal("expected an invalid codec id to be rejected")
	}
	if _, err := ParseSliceHeader(env[:EnvelopeMinLen-1]); err == nil {
		t.Fatal("expected a short envelope to be rejected")
	}
}
