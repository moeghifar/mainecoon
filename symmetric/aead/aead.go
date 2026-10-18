// Package aead is authenticated encryption with associated data: AES-256-GCM (FIPS 197,
// SP 800-38D, Go stdlib) and ChaCha20-Poly1305 (RFC 8439, x/crypto).
//
// Ciphertext is one value, nonce ‖ ciphertext ‖ tag (12 + len(plaintext) + 16 bytes). The
// nonce is always random and generated here; callers never pass one.
package aead

import (
	"crypto/aes"
	stdcipher "crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/moeghifar/mainecoon/drbg"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

// Alg names an AEAD. Its value is the registry ID.
type Alg string

const (
	AES256GCM        Alg = "AES-256-GCM"
	ChaCha20Poly1305 Alg = "ChaCha20-Poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
	Overhead  = NonceSize + TagSize
)

// Every constructor returns an AEAD whose Open(nil, nil, nonce ‖ ct ‖ tag, aad) decrypts;
// GCM also seals that way, and Encrypt draws the ChaCha nonce itself.
var aeads = map[string]func([]byte) (stdcipher.AEAD, error){
	// NewGCMWithRandomNonce draws the nonce inside the Go FIPS module; fips140=only
	// accepts no other GCM constructor, for sealing or opening.
	string(AES256GCM): func(k []byte) (stdcipher.AEAD, error) {
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return stdcipher.NewGCMWithRandomNonce(b)
	},
	string(ChaCha20Poly1305): func(k []byte) (stdcipher.AEAD, error) {
		a, err := chacha20poly1305.New(k)
		return randomNonce{a}, err
	},
}

// randomNonce gives an explicit-nonce AEAD the NewGCMWithRandomNonce Open convention.
type randomNonce struct{ stdcipher.AEAD }

func (r randomNonce) Overhead() int { return NonceSize + r.AEAD.Overhead() }

func (r randomNonce) Open(dst, _, in, aad []byte) ([]byte, error) {
	return r.AEAD.Open(dst, in[:NonceSize], in[NonceSize:], aad)
}

func newAEAD(alg Alg, key []byte) (stdcipher.AEAD, error) {
	f, err := reg.Lookup(aeads, string(alg))
	if err != nil {
		return nil, err
	}
	if len(key) != KeySize {
		return nil, errors.ErrKeySizeInvalid.With(string(alg) + " needs a 32-byte key")
	}
	return f(key)
}

// Encrypt returns nonce ‖ ciphertext ‖ tag.
func Encrypt(alg Alg, key, plaintext, aad []byte) ([]byte, error) {
	a, err := newAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	r, explicit := a.(randomNonce)
	if !explicit {
		return a.Seal(nil, nil, plaintext, aad), nil
	}
	n := make([]byte, NonceSize, NonceSize+len(plaintext)+TagSize)
	if err := drbg.Read(n); err != nil {
		return nil, err
	}
	return r.AEAD.Seal(n, n, plaintext, aad), nil
}

// Decrypt opens nonce ‖ ciphertext ‖ tag. Any wrong key, aad or byte gives ErrDecryptionFailed.
func Decrypt(alg Alg, key, ciphertext, aad []byte) ([]byte, error) {
	a, err := newAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < Overhead {
		return nil, errors.ErrCiphertextEmpty
	}
	pt, err := a.Open(nil, nil, ciphertext, aad)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	return pt, nil
}
