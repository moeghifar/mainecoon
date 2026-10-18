// Package mac is HMAC (FIPS 198-1) over SHA-2 and SHA-3, from the Go stdlib. The key must be
// at least the hash output size (plan F4). Verification is constant time.
// AES-CMAC and AES-GMAC live in symmetric/cmac and symmetric/gmac.
package mac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"hash"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

var hmacs = map[string]func() hash.Hash{
	"HMAC-SHA256":   sha256.New,
	"HMAC-SHA384":   sha512.New384,
	"HMAC-SHA512":   sha512.New,
	"HMAC-SHA3-256": func() hash.Hash { return sha3.New256() },
}

// Algorithms lists the HMACs Sum accepts.
func Algorithms() []string { return reg.IDs(hmacs) }

// MinKeySize is the hash output size.
func MinKeySize(alg string) (int, error) {
	f, err := reg.Lookup(hmacs, alg)
	if err != nil {
		return 0, err
	}
	return f().Size(), nil
}

// Sum returns the tag of data under key.
func Sum(alg string, key, data []byte) ([]byte, error) {
	f, err := reg.Lookup(hmacs, alg)
	if err != nil {
		return nil, err
	}
	if len(key) < f().Size() {
		return nil, errors.ErrKeyTooShort.With(alg)
	}
	m := hmac.New(f, key)
	m.Write(data)
	return m.Sum(nil), nil
}

// Verify returns nil for a valid tag and ErrVerificationFailed otherwise.
func Verify(alg string, key, data, tag []byte) error {
	want, err := Sum(alg, key, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, tag) {
		return errors.ErrVerificationFailed
	}
	return nil
}
