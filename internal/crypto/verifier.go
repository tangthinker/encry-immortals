package vaultcrypto

import (
	"crypto/subtle"
	"fmt"
)

// VerifierPlaintext is the fixed constant sealed into vault.meta.auth_verifier
// (spec §02.4). It is the only password check point in the system.
const VerifierPlaintext = "APEX_AEAD_VERIFY_OK"

// SealAuthVerifier produces the nonce and ciphertext stored in vault.meta.
// ciphertext is 19+16 = 35 bytes.
func SealAuthVerifier(journalKey, vaultID []byte, canonKDF string) (nonce, ciphertext []byte, err error) {
	aad, err := VerifierAAD(VerAlg, vaultID, canonKDF)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = RandomNonce()
	if err != nil {
		return nil, nil, err
	}
	ct, err := Seal(journalKey, nonce, []byte(VerifierPlaintext), aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

// OpenAuthVerifier verifies that journalKey matches the stored verifier.
//
// Every failure mode (wrong password, tampered KDF parameters, cross-vault
// replay, truncated ciphertext) returns the same opaque error: spec §02.9
// forbids building an oracle out of these distinctions.
func OpenAuthVerifier(journalKey, nonce, ciphertext, vaultID []byte, canonKDF string) error {
	if len(nonce) != NonceLen || len(ciphertext) != len(VerifierPlaintext)+TagLen {
		return fmt.Errorf("verifier: unusable verifier fields")
	}
	aad, err := VerifierAAD(VerAlg, vaultID, canonKDF)
	if err != nil {
		return fmt.Errorf("verifier: unusable verifier fields")
	}
	pt, err := Open(journalKey, nonce, ciphertext, aad)
	if err != nil {
		return fmt.Errorf("verifier: authentication failed")
	}
	if subtle.ConstantTimeCompare(pt, []byte(VerifierPlaintext)) != 1 {
		return fmt.Errorf("verifier: authentication failed")
	}
	return nil
}
