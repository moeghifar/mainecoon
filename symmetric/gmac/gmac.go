// Package gmac is AES-256-GMAC (SP 800-38D): GCM authentication over data with an empty
// plaintext, from the Go stdlib. The nonce is random and generated here; the tag value is
// nonce ‖ tag (12 + 16 bytes), so callers handle one value.
package gmac

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = NonceSize + 16
)

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.ErrKeySizeInvalid.With("AES-256-GMAC needs a 32-byte key")
	}
	b, _ := aes.NewCipher(key)
	// NewGCMWithRandomNonce is required by the Go FIPS module in fips140=only;
	// Seal(nil, nil, nil, data) returns nonce ‖ tag.
	return cipher.NewGCMWithRandomNonce(b)
}

// Sum returns nonce ‖ tag over data.
func Sum(key, data []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nil, nil, data), nil //nolint:gosec // G407 false positive: NewGCMWithRandomNonce
}

// Verify returns nil for a valid nonce ‖ tag and ErrVerificationFailed otherwise.
func Verify(key, data, tag []byte) error {
	g, err := gcm(key)
	if err != nil {
		return err
	}
	if len(tag) != TagSize {
		return errors.ErrVerificationFailed
	}
	if _, err := g.Open(nil, nil, tag, data); err != nil {
		return errors.ErrVerificationFailed
	}
	return nil
}
