package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func newSecretBox(encoded string) (cipher.AEAD, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode webhook encryption key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("webhook encryption key must decode to 32 bytes")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("create webhook encryption cipher: %w", err)
	}
	box, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create webhook encryption AEAD: %w", err)
	}
	return box, nil
}

func (s *Store) encryptSecret(secret string) ([]byte, error) {
	nonce := make([]byte, s.box.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate webhook secret nonce: %w", err)
	}
	return s.box.Seal(nonce, nonce, []byte(secret), nil), nil
}

func (s *Store) decryptSecret(ciphertext []byte) (string, error) {
	if len(ciphertext) < s.box.NonceSize() {
		return "", fmt.Errorf("invalid webhook secret ciphertext")
	}
	nonce, payload := ciphertext[:s.box.NonceSize()], ciphertext[s.box.NonceSize():]
	plaintext, err := s.box.Open(nil, nonce, payload, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt webhook secret: %w", err)
	}
	return string(plaintext), nil
}

func (s *Store) DecryptSecret(ciphertext []byte) (string, error) {
	return s.decryptSecret(ciphertext)
}
