// Package rsaoaep is RSA key transport: RSAES-OAEP with SHA-256 and MGF1-SHA-256
// (RFC 8017, NIST SP 800-56B Rev 2 KTS-OAEP), from the Go stdlib.
//
//	pk, sk, _ := rsaoaep.GenerateKey(rsaoaep.RSA3072)
//	ct, _ := rsaoaep.Encrypt(rsaoaep.RSA3072, pk, dek, label)
//	dek, _ := rsaoaep.Decrypt(rsaoaep.RSA3072, sk, ct, label)
//
// It is for wrapping short secrets (a data key), not bulk data: the plaintext is at most
// k - 66 bytes (190 for 2048-bit keys). Keys are PKIX (public) and PKCS#8 (private) DER.
// PKCS#1 v1.5 encryption is not offered (padding oracles).
package rsaoaep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

// Alg names a key size. Its value is the registry ID.
type Alg string

const (
	RSA2048 Alg = "RSA-OAEP-2048"
	RSA3072 Alg = "RSA-OAEP-3072"
	RSA4096 Alg = "RSA-OAEP-4096"
)

var bits = map[string]int{string(RSA2048): 2048, string(RSA3072): 3072, string(RSA4096): 4096}

func size(alg Alg) (int, error) { return reg.Lookup(bits, string(alg)) }

func checkSize(want, got int) error {
	switch {
	case got < 2048:
		return errors.ErrKeyTooShort
	case got != want:
		return errors.ErrKeySizeInvalid
	}
	return nil
}

// GenerateKey returns a PKIX public key and a PKCS#8 private key.
func GenerateKey(alg Alg) (pk, sk []byte, err error) {
	n, err := size(alg)
	if err != nil {
		return nil, nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, n)
	if err != nil {
		return nil, nil, err
	}
	pk, _ = x509.MarshalPKIXPublicKey(&k.PublicKey)
	sk, err = x509.MarshalPKCS8PrivateKey(k)
	return pk, sk, err
}

func private(alg Alg, sk []byte) (*rsa.PrivateKey, error) {
	n, err := size(alg)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(sk)
	rk, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.ErrKeyFormatInvalid
	}
	return rk, checkSize(n, rk.N.BitLen())
}

func public(alg Alg, pk []byte) (*rsa.PublicKey, error) {
	n, err := size(alg)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(pk)
	rk, ok := k.(*rsa.PublicKey)
	if err != nil || !ok {
		return nil, errors.ErrKeyFormatInvalid
	}
	return rk, checkSize(n, rk.N.BitLen())
}

// Public derives the PKIX public key from a PKCS#8 private key.
func Public(alg Alg, sk []byte) ([]byte, error) {
	k, err := private(alg, sk)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}

// Encrypt wraps a short secret to pk. label is optional context bound into the padding.
func Encrypt(alg Alg, pk, plaintext, label []byte) ([]byte, error) {
	k, err := public(alg, pk)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > k.Size()-2*sha256.Size-2 {
		return nil, errors.ErrInputTooLarge.With("RSA-OAEP plaintext too long for this key")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, k, plaintext, label)
}

// Decrypt unwraps. Any failure is ErrDecryptionFailed (no distinction, to avoid an oracle).
func Decrypt(alg Alg, sk, ciphertext, label []byte) ([]byte, error) {
	k, err := private(alg, sk)
	if err != nil {
		return nil, err
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), nil, k, ciphertext, label)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	return pt, nil
}
