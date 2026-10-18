// Package kdf derives keys from high-entropy secrets with HKDF (RFC 5869, SP 800-56C Rev 2
// two-step), from the Go stdlib (cryptop F10). Not for passwords: see package password.
// SP 800-108 and ANSI X9.63 KDFs are not offered: no stdlib or vetted library provides them.
package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

const (
	MinLength = 16
	MaxLength = 512
	MinIKM    = 16
)

var kdfs = map[string]func() hash.Hash{
	"HKDF-SHA256": sha256.New,
	"HKDF-SHA384": sha512.New384,
	"HKDF-SHA512": sha512.New,
}

// Algorithms lists the accepted KDFs.
func Algorithms() []string { return reg.IDs(kdfs) }

// Derive returns length bytes, MinLength <= length <= MaxLength.
func Derive(alg string, ikm, salt, info []byte, length int) ([]byte, error) {
	h, err := reg.Lookup(kdfs, alg)
	if err != nil {
		return nil, err
	}
	if length < MinLength || length > MaxLength {
		return nil, errors.ErrInputInvalid.With("kdf length must be 16..512")
	}
	if len(ikm) < MinIKM {
		return nil, errors.ErrKeyTooShort.With("ikm shorter than 16 bytes")
	}
	return hkdf.Key(h, ikm, salt, string(info), length)
}
