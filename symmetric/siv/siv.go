// Package siv is AES-256-SIV (RFC 5297) from tink-go: deterministic authenticated
// encryption (cryptop F7). Same key, plaintext and aad give the same ciphertext, so it
// reveals equality; use it only where that is wanted (searchable fields).
// Not NIST-approved: unavailable in fips_only.
package siv

import (
	daead "github.com/tink-crypto/tink-go/v2/daead/subtle"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KeySize = daead.AESSIVKeySize // 64: 256-bit CMAC key || 256-bit CTR key
	TagSize = 16
)

// Encrypt returns SIV ‖ ciphertext. aad is one associated-data string (S2V with one component).
func Encrypt(key, pt, aad []byte) ([]byte, error) {
	s, err := cipher(key)
	if err != nil {
		return nil, err
	}
	return s.EncryptDeterministically(pt, aad)
}

// Decrypt reverses Encrypt; any failure is ErrDecryptionFailed.
func Decrypt(key, ct, aad []byte) ([]byte, error) {
	s, err := cipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < TagSize {
		return nil, errors.ErrCiphertextEmpty
	}
	pt, err := s.DecryptDeterministically(ct, aad)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	return pt, nil
}

func cipher(key []byte) (*daead.AESSIV, error) {
	if len(key) != KeySize {
		return nil, errors.ErrKeySizeInvalid.With("AES-256-SIV needs a 64-byte key")
	}
	return daead.NewAESSIV(key)
}
