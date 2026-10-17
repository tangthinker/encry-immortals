package vaultcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// AAD lengths fixed by spec §02.4/§02.5 and §03.2. Encoded as constants so the
// builders and their tests cannot drift apart.
const (
	SliceAADLen    = 54
	JournalAADLen  = 26
	FooterAADLen   = 25
	VerifierAADLen = 49
)

// SliceAAD builds the 54-byte slice envelope AAD (spec §02.5):
//
//	ver_alg(1) || u32be(env_len) || u32be(plain_len) || pack_id(16)
//	|| u64be(slice_offset) || u32be(slice_index) || txn_id(16) || codec(1)
func SliceAAD(verAlg, codec byte, envLen, plainLen uint32, packID []byte, sliceOffset uint64, sliceIndex uint32, txnID []byte) ([]byte, error) {
	if len(packID) != 16 {
		return nil, fmt.Errorf("aad: pack_id must be 16 bytes, got %d", len(packID))
	}
	if len(txnID) != 16 {
		return nil, fmt.Errorf("aad: txn_id must be 16 bytes, got %d", len(txnID))
	}
	b := make([]byte, 0, SliceAADLen)
	b = append(b, verAlg)
	b = binary.BigEndian.AppendUint32(b, envLen)
	b = binary.BigEndian.AppendUint32(b, plainLen)
	b = append(b, packID...)
	b = binary.BigEndian.AppendUint64(b, sliceOffset)
	b = binary.BigEndian.AppendUint32(b, sliceIndex)
	b = append(b, txnID...)
	b = append(b, codec)
	return b, nil
}

// JournalAAD builds the 26-byte journal AAD (spec §02.5):
//
//	ver_alg(1) || codec(1) || u64be(seq) || vault_id(16)
func JournalAAD(verAlg, codec byte, seq uint64, vaultID []byte) ([]byte, error) {
	if len(vaultID) != VaultIDLen {
		return nil, fmt.Errorf("aad: vault_id must be %d bytes, got %d", VaultIDLen, len(vaultID))
	}
	b := make([]byte, 0, JournalAADLen)
	b = append(b, verAlg, codec)
	b = binary.BigEndian.AppendUint64(b, seq)
	b = append(b, vaultID...)
	return b, nil
}

// FooterAAD builds the 25-byte pack footer AAD (spec §03.2):
//
//	ver_alg(1) || pack_id(16) || u64be(footer_start)
func FooterAAD(verAlg byte, packID []byte, footerStart uint64) ([]byte, error) {
	if len(packID) != 16 {
		return nil, fmt.Errorf("aad: pack_id must be 16 bytes, got %d", len(packID))
	}
	b := make([]byte, 0, FooterAADLen)
	b = append(b, verAlg)
	b = append(b, packID...)
	b = binary.BigEndian.AppendUint64(b, footerStart)
	return b, nil
}

// VerifierAAD builds the 49-byte auth_verifier AAD (spec §02.4):
//
//	ver_alg(1) || vault_id(16) || SHA-256(canon_kdf_block)
func VerifierAAD(verAlg byte, vaultID []byte, canonKDF string) ([]byte, error) {
	if len(vaultID) != VaultIDLen {
		return nil, fmt.Errorf("aad: vault_id must be %d bytes, got %d", VaultIDLen, len(vaultID))
	}
	sum := sha256.Sum256([]byte(canonKDF))
	b := make([]byte, 0, VerifierAADLen)
	b = append(b, verAlg)
	b = append(b, vaultID...)
	b = append(b, sum[:]...)
	return b, nil
}

// PathHMAC is the state.db path index (D-13): HMAC-SHA256(PathKey, nfc_path).
func PathHMAC(pathKey []byte, path []byte) [32]byte {
	m := hmac.New(sha256.New, pathKey)
	m.Write(path)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// AnchorMAC authenticates the rollback anchor (spec §04.3):
// HMAC-SHA256(AnchorKey, u64be(seq) || journal_sha256).
func AnchorMAC(anchorKey []byte, seq uint64, journalSHA [32]byte) [32]byte {
	m := hmac.New(sha256.New, anchorKey)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	m.Write(seqb[:])
	m.Write(journalSHA[:])
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}
