// Package sign is digital signatures (cryptop F13 keygen, F14 sign/verify):
//
//	pk, sk, _ := sign.GenerateKey(sign.MLDSA65)
//	sig, _   := sign.Sign(sign.MLDSA65, sk, msg)
//	err      := sign.Verify(sign.MLDSA65, pk, msg, sig)   // nil or VERIFICATION_FAILED
//
// Key encodings (raw bytes; package keys converts to hex, base64, PEM and JWK):
//
//	ECDSA-P256/P384/P521  private: 32/48/66-byte scalar   public: uncompressed point
//	Ed448               private: 57-byte seed        public: 57 bytes
//	Ed25519             private: 32-byte seed        public: 32 bytes
//	RSA-PSS-2048/3072/4096  private: PKCS#8 DER      public: PKIX DER
//	ML-DSA-44/65/87     private: 32-byte seed (FIPS 204 xi)   public: 1312/1952/2592 bytes
//	SLH-DSA-SHA2-128s   private: 64 bytes            public: 32 bytes
//
// ECDSA, ML-DSA and SLH-DSA sign deterministically (RFC 6979; FIPS 204/205 deterministic
// variants), as the cryptop VAPT notes require. RSA uses PSS with SHA-256 and a random salt.
package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"hash"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

// Alg names a signature algorithm. Its value is the registry ID.
type Alg string

const (
	ECDSAP256      Alg = "ECDSA-P256"
	ECDSAP384      Alg = "ECDSA-P384"
	ECDSAP521      Alg = "ECDSA-P521"
	Ed448          Alg = "Ed448"
	RSAPSS2048     Alg = "RSA-PSS-2048"
	Ed25519        Alg = "Ed25519"
	RSAPSS3072     Alg = "RSA-PSS-3072"
	RSAPSS4096     Alg = "RSA-PSS-4096"
	MLDSA44        Alg = "ML-DSA-44"
	MLDSA65        Alg = "ML-DSA-65"
	MLDSA87        Alg = "ML-DSA-87"
	SLHDSASHA2128s Alg = "SLH-DSA-SHA2-128s"
)

// scheme is one signature algorithm.
type scheme interface {
	GenerateKey() (pk, sk []byte, err error)
	Public(sk []byte) ([]byte, error)
	Sign(sk, msg []byte) ([]byte, error)
	// Verify returns nil or ErrVerificationFailed; a malformed key is ErrKeyFormatInvalid.
	Verify(pk, msg, sig []byte) error
}

var schemes = map[string]scheme{
	"ECDSA-P256":        ecdsaScheme{elliptic.P256(), crypto.SHA256, sha256.New},
	"ECDSA-P384":        ecdsaScheme{elliptic.P384(), crypto.SHA384, sha512.New384},
	"ECDSA-P521":        ecdsaScheme{elliptic.P521(), crypto.SHA512, sha512.New},
	"Ed448":             ed448Scheme{},
	"RSA-PSS-2048":      rsaScheme{2048},
	"ML-DSA-44":         mldsaScheme{mldsa.MLDSA44()},
	"Ed25519":           ed25519Scheme{},
	"RSA-PSS-3072":      rsaScheme{3072},
	"RSA-PSS-4096":      rsaScheme{4096},
	"ML-DSA-65":         mldsaScheme{mldsa.MLDSA65()},
	"ML-DSA-87":         mldsaScheme{mldsa.MLDSA87()},
	"SLH-DSA-SHA2-128s": slhScheme{slhdsa.SHA2_128s},
}

func lookup(alg Alg) (scheme, error) { return reg.Lookup(schemes, string(alg)) }

// GenerateKey returns a new key pair.
func GenerateKey(alg Alg) (pk, sk []byte, err error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, nil, err
	}
	return s.GenerateKey()
}

// Public derives the public key from a private key.
func Public(alg Alg, sk []byte) ([]byte, error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, err
	}
	return s.Public(sk)
}

// Sign signs msg.
func Sign(alg Alg, sk, msg []byte) ([]byte, error) {
	s, err := lookup(alg)
	if err != nil {
		return nil, err
	}
	return s.Sign(sk, msg)
}

// Verify returns nil for a valid signature and ErrVerificationFailed otherwise; a malformed
// key is ErrKeyFormatInvalid.
func Verify(alg Alg, pk, msg, sig []byte) error {
	s, err := lookup(alg)
	if err != nil {
		return err
	}
	return s.Verify(pk, msg, sig)
}

var errKey = errors.ErrKeyFormatInvalid

type ecdsaScheme struct {
	curve elliptic.Curve
	hash  crypto.Hash
	newH  func() hash.Hash
}

func (s ecdsaScheme) GenerateKey() ([]byte, []byte, error) {
	k, err := ecdsa.GenerateKey(s.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pk, _ := k.PublicKey.Bytes()
	sk, err := k.Bytes()
	return pk, sk, err
}
func (s ecdsaScheme) priv(sk []byte) (*ecdsa.PrivateKey, error) {
	if len(sk) != (s.curve.Params().BitSize+7)/8 {
		return nil, errors.ErrKeySizeInvalid
	}
	k, err := ecdsa.ParseRawPrivateKey(s.curve, sk)
	if err != nil {
		return nil, errKey
	}
	return k, nil
}
func (s ecdsaScheme) Public(sk []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	return k.PublicKey.Bytes()
}
func (s ecdsaScheme) digest(msg []byte) []byte { h := s.newH(); h.Write(msg); return h.Sum(nil) }
func (s ecdsaScheme) Sign(sk, msg []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	return k.Sign(nil, s.digest(msg), s.hash) // nil rand: RFC 6979 deterministic
}
func (s ecdsaScheme) Verify(pk, msg, sig []byte) error {
	k, err := ecdsa.ParseUncompressedPublicKey(s.curve, pk)
	if err != nil {
		return errKey
	}
	if !ecdsa.VerifyASN1(k, s.digest(msg), sig) {
		return errors.ErrVerificationFailed
	}
	return nil
}

type ed25519Scheme struct{}

func (ed25519Scheme) GenerateKey() ([]byte, []byte, error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	return pk, sk.Seed(), err
}
func (ed25519Scheme) Public(sk []byte) ([]byte, error) {
	if len(sk) != ed25519.SeedSize {
		return nil, errors.ErrKeySizeInvalid
	}
	return ed25519.NewKeyFromSeed(sk).Public().(ed25519.PublicKey), nil
}
func (ed25519Scheme) Sign(sk, msg []byte) ([]byte, error) {
	if len(sk) != ed25519.SeedSize {
		return nil, errors.ErrKeySizeInvalid
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(sk), msg), nil
}
func (ed25519Scheme) Verify(pk, msg, sig []byte) error {
	if len(pk) != ed25519.PublicKeySize {
		return errKey
	}
	if !ed25519.Verify(pk, msg, sig) {
		return errors.ErrVerificationFailed
	}
	return nil
}

type rsaScheme struct{ bits int }

func (s rsaScheme) GenerateKey() ([]byte, []byte, error) {
	k, err := rsa.GenerateKey(rand.Reader, s.bits)
	if err != nil {
		return nil, nil, err
	}
	pk, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	sk, err := x509.MarshalPKCS8PrivateKey(k)
	return pk, sk, err
}
func (s rsaScheme) size(n int) error {
	switch {
	case n < 2048:
		return errors.ErrKeyTooShort
	case n != s.bits:
		return errors.ErrKeySizeInvalid
	}
	return nil
}
func (s rsaScheme) priv(sk []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(sk)
	rk, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errKey
	}
	return rk, s.size(rk.N.BitLen())
}
func (s rsaScheme) Public(sk []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}
func (s rsaScheme) Sign(sk, msg []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, k, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}
func (s rsaScheme) Verify(pk, msg, sig []byte) error {
	k, err := x509.ParsePKIXPublicKey(pk)
	rk, ok := k.(*rsa.PublicKey)
	if err != nil || !ok {
		return errKey
	}
	if err := s.size(rk.N.BitLen()); err != nil {
		return err
	}
	h := sha256.Sum256(msg)
	if rsa.VerifyPSS(rk, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
		return errors.ErrVerificationFailed
	}
	return nil
}

type mldsaScheme struct{ p mldsa.Parameters }

func (s mldsaScheme) GenerateKey() ([]byte, []byte, error) {
	sk, err := mldsa.GenerateKey(s.p)
	if err != nil {
		return nil, nil, err
	}
	return sk.PublicKey().Bytes(), sk.Bytes(), nil
}
func (s mldsaScheme) priv(sk []byte) (*mldsa.PrivateKey, error) {
	if len(sk) != mldsa.PrivateKeySize {
		return nil, errors.ErrKeySizeInvalid
	}
	k, err := mldsa.NewPrivateKey(s.p, sk)
	if err != nil {
		return nil, errKey
	}
	return k, nil
}
func (s mldsaScheme) Public(sk []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}
func (s mldsaScheme) Sign(sk, msg []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	return k.SignDeterministic(msg, nil)
}
func (s mldsaScheme) Verify(pk, msg, sig []byte) error {
	k, err := mldsa.NewPublicKey(s.p, pk)
	if err != nil {
		return errKey
	}
	if mldsa.Verify(k, msg, sig, nil) != nil {
		return errors.ErrVerificationFailed
	}
	return nil
}

type slhScheme struct{ id slhdsa.ID }

func (s slhScheme) GenerateKey() ([]byte, []byte, error) {
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, s.id)
	if err != nil {
		return nil, nil, err
	}
	pk, _ := pub.MarshalBinary()
	sk, err := priv.MarshalBinary()
	return pk, sk, err
}
func (s slhScheme) priv(sk []byte) (*slhdsa.PrivateKey, error) {
	k := slhdsa.PrivateKey{ID: s.id}
	if k.UnmarshalBinary(sk) != nil {
		return nil, errKey
	}
	return &k, nil
}
func (s slhScheme) Public(sk []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	p := k.PublicKey()
	return p.MarshalBinary()
}
func (s slhScheme) Sign(sk, msg []byte) ([]byte, error) {
	k, err := s.priv(sk)
	if err != nil {
		return nil, err
	}
	return slhdsa.SignDeterministic(k, slhdsa.NewMessage(msg), nil)
}
func (s slhScheme) Verify(pk, msg, sig []byte) error {
	k := slhdsa.PublicKey{ID: s.id}
	if k.UnmarshalBinary(pk) != nil {
		return errKey
	}
	if !slhdsa.Verify(&k, slhdsa.NewMessage(msg), sig, nil) {
		return errors.ErrVerificationFailed
	}
	return nil
}

// ed448Scheme is Ed448 (RFC 8032, pure, empty context) from circl.
type ed448Scheme struct{}

func (ed448Scheme) GenerateKey() ([]byte, []byte, error) {
	pk, sk, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk.Seed(), nil
}
func (ed448Scheme) Public(sk []byte) ([]byte, error) {
	if len(sk) != ed448.SeedSize {
		return nil, errors.ErrKeySizeInvalid
	}
	return ed448.NewKeyFromSeed(sk).Public().(ed448.PublicKey), nil
}
func (ed448Scheme) Sign(sk, msg []byte) ([]byte, error) {
	if len(sk) != ed448.SeedSize {
		return nil, errors.ErrKeySizeInvalid
	}
	return ed448.Sign(ed448.NewKeyFromSeed(sk), msg, ""), nil
}
func (ed448Scheme) Verify(pk, msg, sig []byte) error {
	if len(pk) != ed448.PublicKeySize {
		return errKey
	}
	if !ed448.Verify(pk, msg, sig, "") {
		return errors.ErrVerificationFailed
	}
	return nil
}
