// Package keys converts raw key bytes (as produced by sign, kem and hpke) to and from
// the cryptop key formats: RAW_HEX, RAW_BASE64 (base64url), PEM (PKCS#8 / PKIX) and
// JWK (RFC 7517/7518/8037; "AKP" from draft-ietf-cose-dilithium for ML-DSA, ML-KEM, SLH-DSA).
//
// Support matrix (RAW_* work for every algorithm):
//
//	ECDSA-P256/P384/P521, ECDH-P256/P384/P521, HPKE-Classic   PEM, JWK (EC)
//	Ed25519, X25519                                 PEM, JWK (OKP)
//	Ed448                                           JWK (OKP)
//	RSA-PSS-2048/3072/4096, RSA-OAEP-2048/3072/4096 PEM, JWK (RSA)
//	ML-DSA-44/65/87                                 PEM, JWK (AKP)
//	ML-KEM-512/768/1024, SLH-DSA-SHA2-128s, X-Wing  JWK (AKP)
//	HPKE-X25519, HPKE-MLKEM768/1024, HPKE-Hybrid/XWing  RAW only
//	hybrids, HPKE-Hybrid                            RAW only
package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"

	"github.com/moeghifar/mainecoon/asymmetric/hpke"
	"github.com/moeghifar/mainecoon/asymmetric/kem"
	"github.com/moeghifar/mainecoon/asymmetric/rsaoaep"
	"github.com/moeghifar/mainecoon/asymmetric/sign"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/registry"
)

// Format is a key encoding.
type Format string

const (
	RawHex    Format = "RAW_HEX"
	RawBase64 Format = "RAW_BASE64"
	JWK       Format = "JWK"
	PEM       Format = "PEM"
)

var b64 = base64.RawURLEncoding

var ecCurves = map[string]elliptic.Curve{
	"ECDSA-P256": elliptic.P256(), "ECDH-P256": elliptic.P256(), "HPKE-Classic": elliptic.P256(),
	"ECDSA-P384": elliptic.P384(), "ECDH-P384": elliptic.P384(),
	"ECDSA-P521": elliptic.P521(), "ECDH-P521": elliptic.P521(),
}

var akp = map[string]bool{"ML-DSA-44": true, "ML-DSA-65": true, "ML-DSA-87": true, "ML-KEM-512": true, "ML-KEM-768": true, "ML-KEM-1024": true, "SLH-DSA-SHA2-128s": true, "X-Wing": true}

// isRSA reports whether alg uses PKIX / PKCS#8 RSA keys.
func isRSA(alg string) bool {
	return strings.HasPrefix(alg, "RSA-PSS-") || strings.HasPrefix(alg, "RSA-OAEP-")
}

var rsaBits = map[string]int{"RSA-PSS-2048": 2048, "RSA-PSS-3072": 3072, "RSA-PSS-4096": 4096, "RSA-OAEP-2048": 2048, "RSA-OAEP-3072": 3072, "RSA-OAEP-4096": 4096}

var errFormat = errors.ErrKeyFormatInvalid

// Public derives the raw public key from a raw private key for any key-pair algorithm.
func Public(alg string, sk []byte) ([]byte, error) {
	info, err := registry.Lookup(alg)
	if err != nil {
		return nil, err
	}
	switch info.Family {
	case registry.Signature:
		return sign.Public(sign.Alg(alg), sk)
	case registry.KEM:
		return kem.Public(kem.Alg(alg), sk)
	case registry.KeyTransport:
		return rsaoaep.Public(rsaoaep.Alg(alg), sk)
	case registry.HPKE:
		return hpke.Public(hpke.Alg(alg), sk)
	}
	return nil, errFormat.With(alg + " has no key pair")
}

// Encode renders a raw key in format f.
func Encode(alg string, raw []byte, private bool, f Format) (string, error) {
	switch f {
	case RawHex:
		return hex.EncodeToString(raw), nil
	case RawBase64:
		return b64.EncodeToString(raw), nil
	case PEM:
		return encodePEM(alg, raw, private)
	case JWK:
		return encodeJWK(alg, raw, private)
	}
	return "", errFormat.With("unknown format " + string(f))
}

// Decode parses a key in format f back to raw bytes, checking it belongs to alg.
func Decode(alg, s string, private bool, f Format) ([]byte, error) {
	switch f {
	case RawHex:
		b, err := hex.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return nil, errFormat
		}
		return b, nil
	case RawBase64:
		b, err := b64.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
		if err != nil {
			return nil, errFormat
		}
		return b, nil
	case PEM:
		return decodePEM(alg, s, private)
	case JWK:
		return decodeJWK(alg, s, private)
	}
	return nil, errFormat.With("unknown format " + string(f))
}

func encodePEM(alg string, raw []byte, private bool) (string, error) {
	var key any
	var err error
	switch {
	case ecCurves[alg] != nil:
		if private {
			key, err = ecdsa.ParseRawPrivateKey(ecCurves[alg], raw)
		} else {
			key, err = ecdsa.ParseUncompressedPublicKey(ecCurves[alg], raw)
		}
	case alg == "Ed25519":
		if private && len(raw) == ed25519.SeedSize {
			key = ed25519.NewKeyFromSeed(raw)
		} else if !private && len(raw) == ed25519.PublicKeySize {
			key = ed25519.PublicKey(raw)
		} else {
			err = errFormat
		}
	case alg == "X25519":
		if private {
			key, err = ecdh.X25519().NewPrivateKey(raw)
		} else {
			key, err = ecdh.X25519().NewPublicKey(raw)
		}
	case isRSA(alg):
		return armor(raw, private), nil // already PKCS#8 / PKIX DER
	case alg == "ML-DSA-44" || alg == "ML-DSA-65" || alg == "ML-DSA-87":
		p := mldsaParams(alg)
		if private {
			key, err = mldsa.NewPrivateKey(p, raw)
		} else {
			key, err = mldsa.NewPublicKey(p, raw)
		}
	default:
		return "", errFormat.With("PEM is not defined for " + alg)
	}
	if err != nil {
		return "", errFormat
	}
	var der []byte
	if private {
		der, err = x509.MarshalPKCS8PrivateKey(key)
	} else {
		der, err = x509.MarshalPKIXPublicKey(key)
	}
	if err != nil {
		return "", errFormat
	}
	return armor(der, private), nil
}

func armor(der []byte, private bool) string {
	t := "PUBLIC KEY"
	if private {
		t = "PRIVATE KEY"
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: t, Bytes: der}))
}

func decodePEM(alg, s string, private bool) ([]byte, error) {
	blk, _ := pem.Decode([]byte(s))
	want := "PUBLIC KEY"
	if private {
		want = "PRIVATE KEY"
	}
	if blk == nil || blk.Type != want {
		return nil, errFormat.With("expected a " + want + " PEM block")
	}
	var key any
	var err error
	if private {
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	} else {
		key, err = x509.ParsePKIXPublicKey(blk.Bytes)
	}
	if err != nil {
		return nil, errFormat
	}
	var raw []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if ecCurves[alg] != k.Curve {
			return nil, errFormat
		}
		raw, err = k.Bytes()
	case *ecdsa.PublicKey:
		if ecCurves[alg] != k.Curve {
			return nil, errFormat
		}
		raw, err = k.Bytes()
	case ed25519.PrivateKey:
		if alg != "Ed25519" {
			return nil, errFormat
		}
		raw = k.Seed()
	case ed25519.PublicKey:
		if alg != "Ed25519" {
			return nil, errFormat
		}
		raw = k
	case *ecdh.PrivateKey:
		if alg != "X25519" || k.Curve() != ecdh.X25519() {
			return nil, errFormat
		}
		raw = k.Bytes()
	case *ecdh.PublicKey:
		if alg != "X25519" || k.Curve() != ecdh.X25519() {
			return nil, errFormat
		}
		raw = k.Bytes()
	case *rsa.PrivateKey, *rsa.PublicKey:
		if !isRSA(alg) {
			return nil, errFormat
		}
		raw = blk.Bytes
	case *mldsa.PrivateKey:
		if mldsaParams(alg) != k.PublicKey().Parameters() {
			return nil, errFormat
		}
		raw = k.Bytes()
	case *mldsa.PublicKey:
		if mldsaParams(alg) != k.Parameters() {
			return nil, errFormat
		}
		raw = k.Bytes()
	default:
		return nil, errFormat
	}
	if err != nil {
		return nil, errFormat
	}
	if private { // confirm the bytes are a usable private key for alg (e.g. RSA size)
		if _, err := Public(alg, raw); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func mldsaParams(alg string) mldsa.Parameters {
	switch alg {
	case "ML-DSA-44":
		return mldsa.MLDSA44()
	case "ML-DSA-87":
		return mldsa.MLDSA87()
	}
	return mldsa.MLDSA65()
}

type jwk struct {
	Kty  string `json:"kty"`
	Crv  string `json:"crv,omitempty"`
	Alg  string `json:"alg,omitempty"`
	X    string `json:"x,omitempty"`
	Y    string `json:"y,omitempty"`
	D    string `json:"d,omitempty"`
	N    string `json:"n,omitempty"`
	E    string `json:"e,omitempty"`
	P    string `json:"p,omitempty"`
	Q    string `json:"q,omitempty"`
	DP   string `json:"dp,omitempty"`
	DQ   string `json:"dq,omitempty"`
	QI   string `json:"qi,omitempty"`
	Pub  string `json:"pub,omitempty"`
	Priv string `json:"priv,omitempty"`
}

func encodeJWK(alg string, raw []byte, private bool) (string, error) {
	pub := raw
	if private && !isRSA(alg) {
		var err error
		if pub, err = Public(alg, raw); err != nil {
			return "", err
		}
	}
	var j jwk
	switch {
	case ecCurves[alg] != nil:
		size := (ecCurves[alg].Params().BitSize + 7) / 8
		if len(pub) != 1+2*size {
			return "", errFormat
		}
		j = jwk{Kty: "EC", Crv: ecCurves[alg].Params().Name, X: b64.EncodeToString(pub[1 : 1+size]), Y: b64.EncodeToString(pub[1+size:])}
	case alg == "Ed25519" || alg == "X25519" || alg == "Ed448":
		j = jwk{Kty: "OKP", Crv: alg, X: b64.EncodeToString(pub)}
	case isRSA(alg):
		return rsaJWK(raw, private)
	case akp[alg]:
		j = jwk{Kty: "AKP", Alg: alg, Pub: b64.EncodeToString(pub)}
		if private {
			j.Priv = b64.EncodeToString(raw)
		}
		b, _ := json.Marshal(j)
		return string(b), nil
	default:
		return "", errFormat.With("JWK is not defined for " + alg)
	}
	if private {
		j.D = b64.EncodeToString(raw)
	}
	b, _ := json.Marshal(j)
	return string(b), nil
}

func rsaJWK(der []byte, private bool) (string, error) {
	enc := func(i *big.Int) string { return b64.EncodeToString(i.Bytes()) }
	if !private {
		k, err := x509.ParsePKIXPublicKey(der)
		pk, ok := k.(*rsa.PublicKey)
		if err != nil || !ok {
			return "", errFormat
		}
		b, _ := json.Marshal(jwk{Kty: "RSA", N: enc(pk.N), E: enc(big.NewInt(int64(pk.E)))})
		return string(b), nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	sk, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok || len(sk.Primes) != 2 {
		return "", errFormat
	}
	sk.Precompute()
	b, _ := json.Marshal(jwk{Kty: "RSA", N: enc(sk.N), E: enc(big.NewInt(int64(sk.E))), D: enc(sk.D),
		P: enc(sk.Primes[0]), Q: enc(sk.Primes[1]), DP: enc(sk.Precomputed.Dp), DQ: enc(sk.Precomputed.Dq), QI: enc(sk.Precomputed.Qinv)})
	return string(b), nil
}

func decodeJWK(alg, s string, private bool) ([]byte, error) {
	var j jwk
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		return nil, errFormat
	}
	dec := func(v string) []byte { b, _ := b64.DecodeString(v); return b }
	var raw, pub []byte
	switch {
	case ecCurves[alg] != nil:
		size := (ecCurves[alg].Params().BitSize + 7) / 8
		x, y := dec(j.X), dec(j.Y)
		if j.Kty != "EC" || j.Crv != ecCurves[alg].Params().Name || len(x) != size || len(y) != size {
			return nil, errFormat
		}
		pub = append(append([]byte{4}, x...), y...)
		raw = pub
		if private {
			raw = dec(j.D)
		}
	case alg == "Ed25519" || alg == "X25519" || alg == "Ed448":
		if j.Kty != "OKP" || j.Crv != alg {
			return nil, errFormat
		}
		pub, raw = dec(j.X), dec(j.X)
		if private {
			raw = dec(j.D)
		}
	case isRSA(alg):
		return rsaFromJWK(alg, j, private)
	case akp[alg]:
		if j.Kty != "AKP" || j.Alg != alg {
			return nil, errFormat
		}
		pub, raw = dec(j.Pub), dec(j.Pub)
		if private {
			raw = dec(j.Priv)
		}
	default:
		return nil, errFormat.With("JWK is not defined for " + alg)
	}
	if private { // the private key must match the public members
		derived, err := Public(alg, raw)
		if err != nil || (len(pub) > 0 && string(derived) != string(pub)) {
			return nil, errFormat
		}
	}
	if len(raw) == 0 {
		return nil, errFormat
	}
	return raw, nil
}

func rsaFromJWK(alg string, j jwk, private bool) ([]byte, error) {
	num := func(v string) *big.Int { b, _ := b64.DecodeString(v); return new(big.Int).SetBytes(b) }
	if j.Kty != "RSA" {
		return nil, errFormat
	}
	e := num(j.E)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 {
		return nil, errFormat
	}
	pk := rsa.PublicKey{N: num(j.N), E: int(e.Int64())}
	// Check the modulus size before any expensive work (Validate on a huge fake key is a CPU DoS).
	if bits := rsaBits[alg]; pk.N.BitLen() != bits {
		if pk.N.BitLen() < 2048 {
			return nil, errors.ErrKeyTooShort
		}
		return nil, errors.ErrKeySizeInvalid
	}
	var der []byte
	var err error
	if private {
		sk := &rsa.PrivateKey{PublicKey: pk, D: num(j.D), Primes: []*big.Int{num(j.P), num(j.Q)}}
		if sk.Validate() != nil {
			return nil, errFormat
		}
		sk.Precompute()
		der, err = x509.MarshalPKCS8PrivateKey(sk)
	} else {
		der, err = x509.MarshalPKIXPublicKey(&pk)
	}
	if err != nil {
		return nil, errFormat
	}
	if private {
		if _, err := Public(alg, der); err != nil {
			return nil, err
		}
		return der, nil
	}
	if strings.HasPrefix(alg, "RSA-OAEP-") {
		if _, err := rsaoaep.Encrypt(rsaoaep.Alg(alg), der, []byte{0}, nil); err != nil {
			return nil, err // the key itself is unusable for alg (format or size)
		}
	} else if err := sign.Verify(sign.Alg(alg), der, nil, nil); !errors.Is(err, errors.ErrVerificationFailed) {
		return nil, err
	}
	return der, nil
}
