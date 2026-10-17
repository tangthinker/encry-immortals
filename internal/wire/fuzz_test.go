package wire

import (
	"bytes"
	"testing"

	"github.com/tangthinker/encry-immortals/internal/codec"
)

var (
	fuzzKey     = bytes.Repeat([]byte{0x01}, 32)
	fuzzPackID  = bytes.Repeat([]byte{0x02}, 16)
	fuzzTxnID   = bytes.Repeat([]byte{0x03}, 16)
	fuzzVaultID = bytes.Repeat([]byte{0x04}, 16)
)

// FuzzSliceEnvelope feeds arbitrary bytes to the envelope parser/decryptor.
// Contract (spec §12.4): never panic, never allocate more than the declared
// buffer, either reject or return plaintext of the declared length.
func FuzzSliceEnvelope(f *testing.F) {
	plain := []byte("seed payload")
	env, err := SealSlice(fuzzKey, codec.None, len(plain), plain, fuzzPackID, 32, 0, fuzzTxnID)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(env)
	f.Add(env[:EnvelopeMinLen])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > EnvelopeMinLen+1<<20 {
			return
		}
		if h, err := ParseSliceHeader(data); err == nil && int(h.EnvLen) > len(data) {
			t.Fatalf("header accepted an env_len larger than the buffer")
		}
		_, _, _, _ = OpenSlice(fuzzKey, data, fuzzPackID, 32, 0, fuzzTxnID)
	})
}

// FuzzJournalDecode feeds arbitrary bytes to the journal body decoder.
func FuzzJournalDecode(f *testing.F) {
	body, err := EncodeJournalBody(sampleJournal())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	f.Add([]byte{})
	f.Add([]byte{0x98, 0x03})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = DecodeJournalBody(data)
	})
}

// FuzzOpenJournalFile feeds arbitrary bytes to the journal container opener.
func FuzzOpenJournalFile(f *testing.F) {
	body, err := EncodeJournalBody(sampleJournal())
	if err != nil {
		f.Fatal(err)
	}
	raw, err := SealJournalFile(fuzzKey, 1, fuzzVaultID, body)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Add(raw[:JournalFileMinSize-1])

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = OpenJournalFile(fuzzKey, 1, fuzzVaultID, data)
	})
}
