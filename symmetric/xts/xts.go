// Package xts is AES-256-XTS (SP 800-38E, IEEE 1619) from golang.org/x/crypto/xts, for
// storage and volume encryption (cryptop F8). Output length equals input length; there is
// no authentication, so use it only where a length-preserving cipher is required.
package xts

import (
	"crypto/aes"
	"crypto/subtle"

	"golang.org/x/crypto/xts"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KeySize     = 64      // two AES-256 keys
	MaxDataUnit = 1 << 24 // 2^20 blocks, SP 800-38E
	block       = 16
)

// Encrypt encrypts one data unit (sector).
func Encrypt(key, data []byte, sector uint64) ([]byte, error) { return run(key, data, sector, true) }

// Decrypt decrypts one data unit (sector).
func Decrypt(key, data []byte, sector uint64) ([]byte, error) { return run(key, data, sector, false) }

func run(key, data []byte, sector uint64, enc bool) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.ErrKeySizeInvalid.With("AES-256-XTS needs a 64-byte key")
	}
	if subtle.ConstantTimeCompare(key[:32], key[32:]) == 1 {
		return nil, errors.ErrKeySizeInvalid.With("XTS key halves must differ")
	}
	if len(data) > MaxDataUnit {
		return nil, errors.ErrInputTooLarge.With("XTS data unit above 2^20 blocks (SP 800-38E)")
	}
	if len(data) == 0 || len(data)%block != 0 {
		return nil, errors.ErrInputBlockUnaligned
	}
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, errors.ErrKeySizeInvalid
	}
	out := make([]byte, len(data))
	if enc {
		c.Encrypt(out, data, sector)
	} else {
		c.Decrypt(out, data, sector)
	}
	return out, nil
}
