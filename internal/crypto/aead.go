package vaultcrypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewAEAD builds the only AEAD apex uses: XChaCha20-Poly1305 (spec §02.2).
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("aead: key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	return chacha20poly1305.NewX(key)
}

// RandomBytes returns n CSPRNG bytes. The only randomness source in apex.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("rand: negative length %d", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return b, nil
}

// RandomNonce returns a fresh 24-byte random nonce (I18).
func RandomNonce() ([]byte, error) {
	return RandomBytes(NonceLen)
}

// Seal encrypts plaintext with key and nonce, authenticating aad.
// The returned slice is ciphertext||tag.
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("aead: nonce must be %d bytes, got %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts ciphertext (ciphertext||tag) and verifies aad.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("aead: nonce must be %d bytes, got %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
	if len(ciphertext) < TagLen {
		return nil, fmt.Errorf("aead: ciphertext shorter than tag (%d bytes)", len(ciphertext))
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
