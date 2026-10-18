// Package kem is key encapsulation. One call shape for every scheme:
//
//	pk, sk, _ := kem.GenerateKey(kem.MLKEM768)
//	ct, ss, _ := kem.Encapsulate(kem.MLKEM768, pk)   // send ct, keep ss
//	ss, _     := kem.Decapsulate(kem.MLKEM768, sk, ct)
//
// ML-KEM-768/1024 come from the Go stdlib (FIPS 203; private keys are 64-byte seeds);
// ML-KEM-512 from circl (the stdlib has no 512 parameter set), also with a 64-byte seed key.
// DHKEM over P-256, P-384, P-521 and X25519 (RFC 9180, the shared secret is HKDF-derived, never the
// raw DH output), X-Wing (draft-connolly-cfrg-xwing-kem, 32-byte seed private key) and the
// X25519MLKEM768 TLS hybrid come from circl.
package kem

import (
	"crypto/mlkem"

	"github.com/cloudflare/circl/hpke"
	circl "github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/xwing"

	"github.com/moeghifar/mainecoon/drbg"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

// Alg names a KEM. Its value is the registry ID.
type Alg string

const (
	ECDHP256       Alg = "ECDH-P256"
	ECDHP384       Alg = "ECDH-P384"
	ECDHP521       Alg = "ECDH-P521"
	MLKEM512       Alg = "ML-KEM-512"
	XWing          Alg = "X-Wing"
	X25519         Alg = "X25519"
	MLKEM768       Alg = "ML-KEM-768"
	MLKEM1024      Alg = "ML-KEM-1024"
	X25519MLKEM768 Alg = "X25519+ML-KEM-768"
)

type scheme interface {
	generate() (pk, sk []byte, err error)
	public(sk []byte) ([]byte, error)
	encapsulate(pk []byte) (ct, ss []byte, err error)
	decapsulate(sk, ct []byte) ([]byte, error)
}

var schemes = map[string]scheme{
	string(ECDHP256):       circlScheme{hpke.KEM_P256_HKDF_SHA256.Scheme()},
	string(ECDHP384):       circlScheme{hpke.KEM_P384_HKDF_SHA384.Scheme()},
	string(ECDHP521):       circlScheme{hpke.KEM_P521_HKDF_SHA512.Scheme()},
	string(MLKEM512):       seedScheme{mlkem512.Scheme()},
	string(XWing):          circlScheme{xwing.Scheme()},
	string(X25519):         circlScheme{hpke.KEM_X25519_HKDF_SHA256.Scheme()},
	string(MLKEM768):       mlkem768{},
	string(MLKEM1024):      mlkem1024{},
	string(X25519MLKEM768): circlScheme{hybrid.X25519MLKEM768()},
}

func lookup(alg Alg) (scheme, error) { return reg.Lookup(schemes, string(alg)) }

// GenerateKey returns a new key pair.
func GenerateKey(alg Alg) (pk, sk []byte, err error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, nil, err
	}
	return s.generate()
}

// Public derives the public key from a private key.
func Public(alg Alg, sk []byte) ([]byte, error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, err
	}
	return s.public(sk)
}

// Encapsulate returns a ciphertext for pk and the shared secret it carries.
func Encapsulate(alg Alg, pk []byte) (ct, ss []byte, err error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, nil, err
	}
	return s.encapsulate(pk)
}

// Decapsulate recovers the shared secret. ML-KEM uses implicit rejection: a tampered
// ciphertext of the right length yields an unrelated secret, not an error.
func Decapsulate(alg Alg, sk, ct []byte) ([]byte, error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, err
	}
	return s.decapsulate(sk, ct)
}

type circlScheme struct{ s circl.Scheme }

func (c circlScheme) generate() ([]byte, []byte, error) {
	pk, sk, err := c.s.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pkb, _ := pk.MarshalBinary()
	skb, _ := sk.MarshalBinary()
	return pkb, skb, nil
}

func (c circlScheme) public(sk []byte) ([]byte, error) {
	k, err := c.s.UnmarshalBinaryPrivateKey(sk)
	if err != nil {
		return nil, errors.ErrKeyFormatInvalid
	}
	return k.Public().MarshalBinary()
}

func (c circlScheme) encapsulate(pk []byte) ([]byte, []byte, error) {
	k, err := c.s.UnmarshalBinaryPublicKey(pk)
	if err != nil {
		return nil, nil, errors.ErrKeyFormatInvalid
	}
	ct, ss, err := c.s.Encapsulate(k)
	if err != nil {
		return nil, nil, errors.ErrKeyFormatInvalid
	}
	return ct, ss, nil
}

func (c circlScheme) decapsulate(sk, ct []byte) ([]byte, error) {
	k, err := c.s.UnmarshalBinaryPrivateKey(sk)
	if err != nil {
		return nil, errors.ErrKeyFormatInvalid
	}
	if len(ct) != c.s.CiphertextSize() {
		return nil, errors.ErrDecapsulationFailed
	}
	ss, err := c.s.Decapsulate(k, ct)
	if err != nil {
		return nil, errors.ErrDecapsulationFailed
	}
	return ss, nil
}

type mlkem768 struct{}

func (mlkem768) generate() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

func (mlkem768) public(sk []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(sk)
	if err != nil {
		return nil, errors.ErrKeySizeInvalid
	}
	return dk.EncapsulationKey().Bytes(), nil
}

func (mlkem768) encapsulate(pk []byte) ([]byte, []byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(pk)
	if err != nil {
		return nil, nil, errors.ErrKeyFormatInvalid
	}
	ss, ct := ek.Encapsulate()
	return ct, ss, nil
}

func (mlkem768) decapsulate(sk, ct []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(sk)
	if err != nil {
		return nil, errors.ErrKeySizeInvalid
	}
	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, errors.ErrDecapsulationFailed
	}
	return ss, nil
}

type mlkem1024 struct{}

func (mlkem1024) generate() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

func (mlkem1024) public(sk []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey1024(sk)
	if err != nil {
		return nil, errors.ErrKeySizeInvalid
	}
	return dk.EncapsulationKey().Bytes(), nil
}

func (mlkem1024) encapsulate(pk []byte) ([]byte, []byte, error) {
	ek, err := mlkem.NewEncapsulationKey1024(pk)
	if err != nil {
		return nil, nil, errors.ErrKeyFormatInvalid
	}
	ss, ct := ek.Encapsulate()
	return ct, ss, nil
}

func (mlkem1024) decapsulate(sk, ct []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey1024(sk)
	if err != nil {
		return nil, errors.ErrKeySizeInvalid
	}
	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, errors.ErrDecapsulationFailed
	}
	return ss, nil
}

// seedScheme stores the private key as the KEM's derivation seed (64 bytes for ML-KEM,
// the FIPS 203 d ‖ z), matching the stdlib ML-KEM-768/1024 encoding.
type seedScheme struct{ s circl.Scheme }

func (c seedScheme) derive(seed []byte) (circl.PublicKey, circl.PrivateKey, error) {
	if len(seed) != c.s.SeedSize() {
		return nil, nil, errors.ErrKeySizeInvalid
	}
	pk, sk := c.s.DeriveKeyPair(seed)
	return pk, sk, nil
}

func (c seedScheme) generate() ([]byte, []byte, error) {
	seed := make([]byte, c.s.SeedSize())
	if err := drbg.Read(seed); err != nil {
		return nil, nil, err
	}
	pk, err := c.public(seed)
	return pk, seed, err
}

func (c seedScheme) public(seed []byte) ([]byte, error) {
	pk, _, err := c.derive(seed)
	if err != nil {
		return nil, err
	}
	return pk.MarshalBinary()
}

func (c seedScheme) encapsulate(pk []byte) ([]byte, []byte, error) {
	return circlScheme(c).encapsulate(pk)
}

func (c seedScheme) decapsulate(seed, ct []byte) ([]byte, error) {
	_, sk, err := c.derive(seed)
	if err != nil {
		return nil, err
	}
	if len(ct) != c.s.CiphertextSize() {
		return nil, errors.ErrDecapsulationFailed
	}
	ss, err := c.s.Decapsulate(sk, ct)
	if err != nil {
		return nil, errors.ErrDecapsulationFailed
	}
	return ss, nil
}
