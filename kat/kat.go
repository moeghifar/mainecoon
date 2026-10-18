// Package kat is the power-on self-test (cryptop plan/testing.md, KAT-001..KAT-024 plus
// one known-answer test for every other algorithm). A service runs it at startup and
// refuses to start on any failure (mainecoon.New does this), and re-runs it on a timer
// (CHT-003). Vectors are published values: NIST ACVP, RFCs, Wycheproof.
package kat

import (
	"bytes"
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/pbkdf2"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/moeghifar/mainecoon/asymmetric/hpke"
	"github.com/moeghifar/mainecoon/asymmetric/kem"
	"github.com/moeghifar/mainecoon/asymmetric/rsaoaep"
	"github.com/moeghifar/mainecoon/asymmetric/sign"
	"github.com/moeghifar/mainecoon/drbg"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/hash"
	"github.com/moeghifar/mainecoon/kdf"
	"github.com/moeghifar/mainecoon/mac"
	"github.com/moeghifar/mainecoon/symmetric/aead"
	"github.com/moeghifar/mainecoon/symmetric/cmac"
	"github.com/moeghifar/mainecoon/symmetric/ff1"
	"github.com/moeghifar/mainecoon/symmetric/gmac"
	"github.com/moeghifar/mainecoon/symmetric/kwp"
	"github.com/moeghifar/mainecoon/symmetric/siv"
	"github.com/moeghifar/mainecoon/symmetric/stream"
	"github.com/moeghifar/mainecoon/symmetric/xts"
	"golang.org/x/crypto/chacha20poly1305"
)

// Result is one known-answer test outcome.
type Result struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Name      string `json:"name"`
	Passed    bool   `json:"passed"`
	Detail    string `json:"detail,omitempty"`
}

type test struct {
	id, alg, name string
	run           func() error
}

// Run executes every test whose algorithm permitted reports true (nil runs all).
// Tests for algorithms a policy does not allow are skipped, so a fips_only build
// without ML-DSA support still starts.
func Run(permitted func(alg string) bool) []Result {
	var out []Result
	for _, t := range tests {
		if permitted != nil && !permitted(t.alg) {
			continue
		}
		r := Result{ID: t.id, Algorithm: t.alg, Name: t.name, Passed: true}
		if err := safe(t.run); err != nil {
			r.Passed, r.Detail = false, err.Error()
		}
		out = append(out, r)
	}
	return out
}

func safe(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return f()
}

// Passed reports whether every result passed (and at least one ran).
func Passed(rs []Result) bool {
	for _, r := range rs {
		if !r.Passed {
			return false
		}
	}
	return len(rs) > 0
}

// Err returns ErrKATFailure naming the failed tests, or nil.
func Err(rs []Result) error {
	if Passed(rs) {
		return nil
	}
	var failed []string
	for _, r := range rs {
		if !r.Passed {
			failed = append(failed, r.ID+" "+r.Algorithm)
		}
	}
	return errors.ErrKATFailure.With(fmt.Sprint(failed))
}

//go:embed vectors/vectors.json
var vectorsJSON []byte

type hx []byte

func (h *hx) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

var v = load()

type vectorSet struct {
	MLKEM768KeyGen struct{ D, Z, Ek hx }                        `json:"mlkem768_keygen"`
	MLKEM768Encap  struct{ Ek, M, C, K hx }                     `json:"mlkem768_encap"`
	MLDSA65KeyGen  struct{ Seed, Pk hx }                        `json:"mldsa65_keygen"`
	XWing          struct{ Seed, Ct, Ss hx }                    `json:"xwing"`
	ECDSAP521      struct{ Pk, Msg, Sig hx }                    `json:"ecdsa_p521"`
	Ed448          struct{ Pk, Msg, Sig hx }                    `json:"ed448"`
	MLDSA44        struct{ Pk, Msg, Sig hx }                    `json:"mldsa44"`
	RSAPSS2048     struct{ Pk, Msg, Sig hx }                    `json:"rsapss2048"`
	DHKEMP521      struct{ SkRm, Enc, Ss hx }                   `json:"dhkem_p521"`
	MLKEM512       struct{ Seed, C, K hx }                      `json:"mlkem512"`
	OAEP2048       oaepVec                                      `json:"oaep2048"`
	OAEP3072       oaepVec                                      `json:"oaep3072"`
	OAEP4096       oaepVec                                      `json:"oaep4096"`
	HPKEX25519     struct{ SkRm, Info, Enc, Aad, Ct, Pt hx }    `json:"hpke_x25519"`
	MLDSA65SigVer  struct{ Pk, Message, Context, Signature hx } `json:"mldsa65_sigver"`
	SLHDSASigVer   struct{ Pk, Message, Context, Signature hx } `json:"slhdsa_sha2_128s_sigver"`
	XTS            struct{ Key, TweakValue, Pt, Ct hx }         `json:"xts256_encrypt"`
	SIV            struct{ Key, Aad, Msg, Ct hx }               `json:"siv512"`
	DHKEMP256      struct {
		SkEm, PkRm, SkRm, Enc, Info, Aad, Ct, Pt hx
		SS                                       hx `json:"shared_secret"`
	} `json:"dhkem_p256"`
	DHKEMX25519 struct {
		SkEm, PkRm, SkRm, Enc hx
		SS                    hx `json:"shared_secret"`
	} `json:"dhkem_x25519"`
	KWP      struct{ Key, Pt, Ct hx }             `json:"kwp256"`
	HKDF384J struct{ Ikm, Salt, Info, Okm hx }    `json:"hkdf_sha384"`
	HKDF512J struct{ Ikm, Salt, Info, Okm hx }    `json:"hkdf_sha512"`
	HMACSHA3 struct{ Key, Msg, Tag hx }           `json:"hmac_sha3_256"`
	RSA3072  struct{ PublicKeyDer, Msg, Sig hx }  `json:"rsa_pss_3072"`
	RSA4096  struct{ PublicKeyDer, Msg, Sig hx }  `json:"rsa_pss_4096"`
	ECDH384  struct{ Private, Public, Shared hx } `json:"ecdh_p384"`
	PBKDF2   struct {
		Password, Salt, Dk hx
		IterationCount     int
	} `json:"pbkdf2_sha256"`
}

// load runs during package variable initialisation, before tests (which reads v) is built.
func load() vectorSet {
	var s vectorSet
	if err := json.Unmarshal(vectorsJSON, &s); err != nil {
		panic("kat: embedded vectors: " + err.Error())
	}
	return s
}

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func eq(got []byte, err error, want []byte) error {
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("output does not match the published vector")
	}
	return nil
}

func expect(cond bool, msg string) error {
	if !cond {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// GCM spec test case 16 (AES-256 with AAD).
var (
	gcmKey   = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	gcmNonce = h("cafebabefacedbaddecaf888")
	gcmPT    = h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	gcmAAD   = h("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	gcmCT    = h("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
	gcmTag   = h("76fc6ece0f4e1768cddf8853bb2d551b")
	hmacKey  = bytes.Repeat([]byte{0xaa}, 131) // RFC 4231 test case 6
	hmacMsg  = []byte("Test Using Larger Than Block-Size Key - Hash Key First")
)

var tests = []test{
	{"KAT-001", "AES-256-GCM", "encrypt, GCM spec test case 16 (fips140=only: seal/open, the module's GCM CAST covers fixed-IV encryption)", func() error {
		if !fips140.Enforced() { // fixed-IV GCM is refused in fips140=only mode
			b, _ := aes.NewCipher(gcmKey)
			a, _ := stdcipher.NewGCM(b)
			if err := eq(a.Seal(nil, gcmNonce, gcmPT, gcmAAD), nil, append(bytes.Clone(gcmCT), gcmTag...)); err != nil {
				return err
			}
		}
		ct, err := aead.Encrypt(aead.AES256GCM, gcmKey, gcmPT, gcmAAD)
		if err != nil {
			return err
		}
		pt, err := aead.Decrypt(aead.AES256GCM, gcmKey, ct, gcmAAD)
		return eq(pt, err, gcmPT)
	}},
	{"KAT-002", "AES-256-GCM", "decrypt, GCM spec test case 16", func() error {
		pt, err := aead.Decrypt(aead.AES256GCM, gcmKey, gcmSealed(), gcmAAD)
		return eq(pt, err, gcmPT)
	}},
	{"KAT-003", "AES-256-GCM", "AAD binding: altered AAD fails", func() error {
		_, err := aead.Decrypt(aead.AES256GCM, gcmKey, gcmSealed(), gcmAAD[1:])
		return expect(errors.Is(err, errors.ErrDecryptionFailed), "altered AAD opened")
	}},
	{"KAT-004", "AES-256-XTS", "encrypt + decrypt, IEEE 1619 vector 10", func() error {
		ct, err := xts.Encrypt(v.XTS.Key, v.XTS.Pt, binary.LittleEndian.Uint64(v.XTS.TweakValue))
		if err := eq(ct, err, v.XTS.Ct); err != nil {
			return err
		}
		pt, err := xts.Decrypt(v.XTS.Key, v.XTS.Ct, binary.LittleEndian.Uint64(v.XTS.TweakValue))
		return eq(pt, err, v.XTS.Pt)
	}},
	{"KAT-005", "AES-256-CMAC", "SP 800-38B D.3 example 2", func() error {
		t, err := cmac.Sum(h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), h("6bc1bee22e409f96e93d7e117393172a"))
		return eq(t, err, h("28a7023f452e8f82bd4bf28d8c37c35c"))
	}},
	{"KAT-007", "AES-256-SIV", "encrypt + decrypt, Wycheproof 512-bit key", func() error {
		ct, err := siv.Encrypt(v.SIV.Key, v.SIV.Msg, v.SIV.Aad)
		if err := eq(ct, err, v.SIV.Ct); err != nil {
			return err
		}
		pt, err := siv.Decrypt(v.SIV.Key, v.SIV.Ct, v.SIV.Aad)
		return eq(pt, err, v.SIV.Msg)
	}},
	{"KAT-008", "FF1", "encrypt + decrypt, SP 800-38G sample 7", func() error {
		key := h("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
		ct, err := ff1.Encrypt(key, "0123456789", nil, ff1.Numeric)
		if err != nil || ct != "6657667009" {
			return fmt.Errorf("encrypt mismatch")
		}
		pt, err := ff1.Decrypt(key, ct, nil, ff1.Numeric)
		return expect(err == nil && pt == "0123456789", "decrypt mismatch")
	}},
	{"KAT-009", "SHA-256", `FIPS 180-4 "abc"`, digest("SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")},
	{"KAT-010", "SHA-384", `FIPS 180-4 "abc"`, digest("SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")},
	{"KAT-011", "SHA-512", `FIPS 180-4 "abc"`, digest("SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")},
	{"KAT-012", "SHA3-256", `FIPS 202 "abc"`, digest("SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")},
	{"KAT-013", "SHA3-512", `FIPS 202 "abc"`, digest("SHA3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")},
	{"KAT-014", "SHAKE256", "FIPS 202 empty input, 64-byte output", func() error {
		o, err := hash.XOF("SHAKE256", nil, 64)
		return eq(o, err, h("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"))
	}},
	{"KAT-015", "HMAC-SHA256", "RFC 4231 test case 6", func() error {
		t, err := mac.Sum("HMAC-SHA256", hmacKey, hmacMsg)
		return eq(t, err, h("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))
	}},
	{"KAT-016", "HMAC-SHA384", "RFC 4231 test case 6", func() error {
		t, err := mac.Sum("HMAC-SHA384", hmacKey, hmacMsg)
		return eq(t, err, h("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"))
	}},
	{"KAT-017", "ECDSA-P256", "sign + verify, RFC 6979 A.2.5", func() error {
		sk := h("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
		s, err := sign.Sign(sign.ECDSAP256, sk, []byte("sample"))
		// DER of (r, s) from RFC 6979 A.2.5, SHA-256, "sample".
		want := h("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
		if err := eq(s, err, want); err != nil {
			return err
		}
		return verify("ECDSA-P256", sk, []byte("sample"), s)
	}},
	{"KAT-018", "Ed25519", "sign + verify, RFC 8032 7.1 test 1", func() error {
		sk := h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
		s, err := sign.Sign(sign.Ed25519, sk, nil)
		if err := eq(s, err, h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")); err != nil {
			return err
		}
		return verify("Ed25519", sk, nil, s)
	}},
	{"KAT-019", "ECDH-P256", "DHKEM(P-256) decap, RFC 9180 A.3; encap round trip", dhkem(kem.ECDHP256, v.DHKEMP256.SkRm, v.DHKEMP256.Enc, v.DHKEMP256.SS)},
	{"KAT-020", "HKDF-SHA256", "RFC 5869 test case 1", func() error {
		o, err := kdf.Derive("HKDF-SHA256", h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), h("000102030405060708090a0b0c"), h("f0f1f2f3f4f5f6f7f8f9"), 42)
		return eq(o, err, h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
	}},
	{"KAT-021", "PBKDF2-SHA256", "Wycheproof, 4096 iterations (the 600k floor applies to callers, not the algorithm)", func() error {
		x := v.PBKDF2
		k, err := pbkdf2.Key(sha256.New, string(x.Password), x.Salt, x.IterationCount, len(x.Dk))
		return eq(k, err, x.Dk)
	}},
	{"KAT-022", "CTR_DRBG-AES256", "crypto/rand output (the Go FIPS module runs its own CTR_DRBG CAST)", func() error {
		a, err1 := drbg.Bytes(32)
		b, err2 := drbg.Bytes(32)
		return expect(err1 == nil && err2 == nil && !bytes.Equal(a, b), "random generator unhealthy")
	}},
	{"KAT-023", "ML-KEM-768", "keyGen + encap (ACVP), decap round trip", func() error {
		pk, err := keyPub("ML-KEM-768", append(bytes.Clone(v.MLKEM768KeyGen.D), v.MLKEM768KeyGen.Z...))
		if err := eq(pk, err, v.MLKEM768KeyGen.Ek); err != nil {
			return fmt.Errorf("keyGen: %w", err)
		}
		ek, err := mlkem.NewEncapsulationKey768(v.MLKEM768Encap.Ek)
		if err != nil {
			return err
		}
		k, c, err := mlkemtest.Encapsulate768(ek, v.MLKEM768Encap.M)
		if err != nil || !bytes.Equal(k, v.MLKEM768Encap.K) || !bytes.Equal(c, v.MLKEM768Encap.C) {
			return fmt.Errorf("encap mismatch")
		}
		return roundTripKEM("ML-KEM-768")
	}},
	{"KAT-024", "ML-DSA-65", "keyGen + sigVer (ACVP), sign + verify", func() error {
		pk, err := keyPub("ML-DSA-65", v.MLDSA65KeyGen.Seed)
		if err := eq(pk, err, v.MLDSA65KeyGen.Pk); err != nil {
			return fmt.Errorf("keyGen: %w", err)
		}
		k, err := mldsa.NewPublicKey(mldsa.MLDSA65(), v.MLDSA65SigVer.Pk)
		if err != nil || mldsa.Verify(k, v.MLDSA65SigVer.Message, v.MLDSA65SigVer.Signature, &mldsa.Options{Context: string(v.MLDSA65SigVer.Context)}) != nil {
			return fmt.Errorf("sigVer failed")
		}
		return verify("ML-DSA-65", v.MLDSA65KeyGen.Seed, []byte("kat"), nil)
	}},
	{"KAT-025", "ML-DSA-87", "sign + verify", func() error { return roundTripSig("ML-DSA-87") }},
	{"KAT-026", "SLH-DSA-SHA2-128s", "sigVer (ACVP), sign + verify", func() error {
		k := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
		if k.UnmarshalBinary(v.SLHDSASigVer.Pk) != nil || !slhdsa.Verify(&k, slhdsa.NewMessage(v.SLHDSASigVer.Message), v.SLHDSASigVer.Signature, v.SLHDSASigVer.Context) {
			return fmt.Errorf("sigVer failed")
		}
		return roundTripSig("SLH-DSA-SHA2-128s")
	}},
	{"KAT-027", "ECDSA-P384", "sign + verify", func() error { return roundTripSig("ECDSA-P384") }},
	{"KAT-028", "RSA-PSS-3072", "verify, Wycheproof (SHA-256, MGF1-SHA256, 32-byte salt)", rsaVerify("RSA-PSS-3072", func() ([]byte, []byte, []byte) { return v.RSA3072.PublicKeyDer, v.RSA3072.Msg, v.RSA3072.Sig })},
	{"KAT-042", "RSA-PSS-4096", "verify, Wycheproof (SHA-256, MGF1-SHA256, 32-byte salt)", rsaVerify("RSA-PSS-4096", func() ([]byte, []byte, []byte) { return v.RSA4096.PublicKeyDer, v.RSA4096.Msg, v.RSA4096.Sig })},
	{"KAT-043", "ECDH-P384", "ECDH Wycheproof vector, DHKEM(P-384) encap + decap", func() error {
		sk, err := ecdh.P384().NewPrivateKey(v.ECDH384.Private)
		if err != nil {
			return err
		}
		pk, err := ecdh.P384().NewPublicKey(v.ECDH384.Public)
		if err != nil {
			return err
		}
		z, err := sk.ECDH(pk)
		if err := eq(z, err, v.ECDH384.Shared); err != nil {
			return err
		}
		return roundTripKEM("ECDH-P384")
	}},
	{"KAT-044", "SHAKE128", "FIPS 202 empty input, 32-byte output", func() error {
		o, err := hash.XOF("SHAKE128", nil, 32)
		return eq(o, err, h("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"))
	}},
	{"KAT-045", "HMAC-SHA3-256", "Wycheproof", func() error {
		t, err := mac.Sum("HMAC-SHA3-256", v.HMACSHA3.Key, v.HMACSHA3.Msg)
		return eq(t, err, v.HMACSHA3.Tag)
	}},
	{"KAT-046", "HKDF-SHA384", "Wycheproof", func() error {
		x := v.HKDF384J
		o, err := kdf.Derive("HKDF-SHA384", x.Ikm, x.Salt, x.Info, len(x.Okm))
		return eq(o, err, x.Okm)
	}},
	{"KAT-047", "HKDF-SHA512", "Wycheproof", func() error {
		x := v.HKDF512J
		o, err := kdf.Derive("HKDF-SHA512", x.Ikm, x.Salt, x.Info, len(x.Okm))
		return eq(o, err, x.Okm)
	}},
	{"KAT-048", "AES-256-GCM-HKDF-1MB", "decrypt known tink-go ciphertext", func() error {
		r, err := stream.Decrypt(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			bytes.NewReader(h("28f632d85c98d2d96e6c91f180235ff32a0be5eb00e272036a087b9b7ffb7ca798037f643f1c34b65ec69c6c9e896a50c1dbb6f8706aa231f73616a7acc0a3f1ce6800dcab638ed83c552c77d05a0f")), []byte("mainecoon-kat"))
		if err != nil {
			return err
		}
		pt, err := io.ReadAll(r)
		return eq(pt, err, []byte("mainecoon streaming KAT"))
	}},
	{"KAT-049", "ECDSA-P521", "verify, Wycheproof (SHA-512)", sigVerify(sign.ECDSAP521, func() (pk, msg, s []byte) { return v.ECDSAP521.Pk, v.ECDSAP521.Msg, v.ECDSAP521.Sig })},
	{"KAT-050", "Ed448", "verify, Wycheproof", sigVerify(sign.Ed448, func() (pk, msg, s []byte) { return v.Ed448.Pk, v.Ed448.Msg, v.Ed448.Sig })},
	{"KAT-051", "ML-DSA-44", "verify, Wycheproof", sigVerify(sign.MLDSA44, func() (pk, msg, s []byte) { return v.MLDSA44.Pk, v.MLDSA44.Msg, v.MLDSA44.Sig })},
	{"KAT-052", "RSA-PSS-2048", "verify, Wycheproof (SHA-256, MGF1-SHA256, 32-byte salt)", sigVerify(sign.RSAPSS2048, func() (pk, msg, s []byte) { return v.RSAPSS2048.Pk, v.RSAPSS2048.Msg, v.RSAPSS2048.Sig })},
	{"KAT-053", "ECDH-P521", "DHKEM(P-521) decap, RFC 9180; encap round trip", dhkem(kem.ECDHP521, v.DHKEMP521.SkRm, v.DHKEMP521.Enc, v.DHKEMP521.Ss)},
	{"KAT-054", "ML-KEM-512", "decap, Wycheproof; encap round trip", func() error {
		k, err := kem.Decapsulate(kem.MLKEM512, v.MLKEM512.Seed, v.MLKEM512.C)
		if err := eq(k, err, v.MLKEM512.K); err != nil {
			return err
		}
		return roundTripKEM(kem.MLKEM512)
	}},
	{"KAT-055", "X-Wing", "decap, draft-connolly-cfrg-xwing-kem vector 1; encap round trip", func() error {
		ss, err := kem.Decapsulate(kem.XWing, v.XWing.Seed, v.XWing.Ct)
		if err := eq(ss, err, v.XWing.Ss); err != nil {
			return err
		}
		return roundTripKEM(kem.XWing)
	}},
	{"KAT-056", "RSA-OAEP-2048", "decrypt, Wycheproof (SHA-256, MGF1-SHA256)", oaepDecrypt(rsaoaep.RSA2048, &v.OAEP2048)},
	{"KAT-057", "RSA-OAEP-3072", "decrypt, Wycheproof (SHA-256, MGF1-SHA256)", oaepDecrypt(rsaoaep.RSA3072, &v.OAEP3072)},
	{"KAT-058", "RSA-OAEP-4096", "decrypt, Wycheproof (SHA-256, MGF1-SHA256)", oaepDecrypt(rsaoaep.RSA4096, &v.OAEP4096)},
	{"KAT-059", "HPKE-XWing", "encrypt + decrypt (no published vectors for the draft suite yet)", func() error {
		pk, sk, err := hpke.GenerateKey(hpke.XWing)
		if err != nil {
			return err
		}
		ct, err := hpke.Encrypt(hpke.XWing, pk, []byte("kat"), []byte("aad"))
		if err != nil {
			return err
		}
		pt, err := hpke.Decrypt(hpke.XWing, sk, ct, []byte("aad"))
		return eq(pt, err, []byte("kat"))
	}},
	{"KAT-060", "HPKE-X25519", "decrypt, RFC 9180 DHKEM(X25519)/HKDF-SHA256/AES-256-GCM", func() error {
		x := v.HPKEX25519
		pt, err := hpke.DecryptWithInfo(hpke.X25519, x.SkRm, x.Info, append(bytes.Clone(x.Enc), x.Ct...), x.Aad)
		return eq(pt, err, x.Pt)
	}},
	{"KAT-061", "HPKE-MLKEM768", "encrypt + decrypt (no published vectors for the draft suite yet)", hpkeRoundTrip(hpke.MLKEM768)},
	{"KAT-062", "HPKE-MLKEM1024", "encrypt + decrypt (no published vectors for the draft suite yet)", hpkeRoundTrip(hpke.MLKEM1024)},
	{"KAT-029", "X25519", "DHKEM(X25519) decap, RFC 9180 A.1; encap round trip", dhkem(kem.X25519, v.DHKEMX25519.SkRm, v.DHKEMX25519.Enc, v.DHKEMX25519.SS)},
	{"KAT-030", "ML-KEM-1024", "encap + decap", func() error { return roundTripKEM(kem.MLKEM1024) }},
	{"KAT-031", "X25519+ML-KEM-768", "hybrid encap + decap", func() error { return roundTripKEM(kem.X25519MLKEM768) }},
	{"KAT-033", "HPKE-Classic", "open, RFC 9180 A.3 (DHKEM(P-256), HKDF-SHA256, AES-256-GCM)", func() error {
		pt, err := hpke.DecryptWithInfo(hpke.Classic, v.DHKEMP256.SkRm, v.DHKEMP256.Info, append(bytes.Clone(v.DHKEMP256.Enc), v.DHKEMP256.Ct...), v.DHKEMP256.Aad)
		return eq(pt, err, v.DHKEMP256.Pt)
	}},
	{"KAT-034", "HPKE-Hybrid", "seal + open", func() error {
		pk, sk, err := hpke.GenerateKey(hpke.Hybrid)
		if err != nil {
			return err
		}
		ct, err := hpke.Encrypt(hpke.Hybrid, pk, []byte("kat"), []byte("aad"))
		if err != nil {
			return err
		}
		pt, err := hpke.Decrypt(hpke.Hybrid, sk, ct, []byte("aad"))
		return eq(pt, err, []byte("kat"))
	}},
	{"KAT-035", "ChaCha20-Poly1305", "RFC 8439 2.8.2", func() error {
		a, err := chacha20poly1305.New(h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
		if err != nil {
			return err
		}
		out := a.Seal(nil, h("070000004041424344454647"), []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."), h("50515253c0c1c2c3c4c5c6c7"))
		return expect(hex.EncodeToString(out[len(out)-16:]) == "1ae10b594f09e26a7e902ecbd0600691", "tag mismatch")
	}},
	{"KAT-036", "AES-256-GMAC", "verify, GCM spec test case 13", func() error {
		key, tag := make([]byte, 32), h("000000000000000000000000530f8afbc74536b9a963b4f1c4cb738b")
		if err := gmac.Verify(key, nil, tag); err != nil {
			return fmt.Errorf("published tag rejected")
		}
		tag[12] ^= 1
		return expect(gmac.Verify(key, nil, tag) != nil, "altered tag verified")
	}},
	{"KAT-037", "AES-256-KWP", "wrap + unwrap, NIST ACVP", func() error {
		w, err := kwp.Wrap(v.KWP.Key, v.KWP.Pt)
		if err := eq(w, err, v.KWP.Ct); err != nil {
			return err
		}
		k, err := kwp.Unwrap(v.KWP.Key, w)
		return eq(k, err, v.KWP.Pt)
	}},
	{"KAT-040", "SHA3-384", `FIPS 202 "abc"`, digest("SHA3-384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")},
	{"KAT-041", "HMAC-SHA512", "RFC 4231 test case 6", func() error {
		t, err := mac.Sum("HMAC-SHA512", hmacKey, hmacMsg)
		return eq(t, err, h("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"))
	}},
}

func digest(alg, want string) func() error {
	return func() error {
		d, err := hash.Sum(alg, []byte("abc"))
		return eq(d, err, h(want))
	}
}

func rsaVerify(alg string, vec func() (pk, msg, s []byte)) func() error {
	return func() error {
		pk, msg, s := vec()
		if err := sign.Verify(sign.Alg(alg), pk, msg, s); err != nil {
			return fmt.Errorf("published signature rejected: %v", err)
		}
		bad := bytes.Clone(s)
		bad[0] ^= 1
		return expect(sign.Verify(sign.Alg(alg), pk, msg, bad) != nil, "altered signature verified")
	}
}

func keyPub(alg string, sk []byte) ([]byte, error) {
	if pk, err := sign.Public(sign.Alg(alg), sk); !errors.Is(err, errors.ErrAlgorithmDisabled) {
		return pk, err
	}
	return kem.Public(kem.Alg(alg), sk)
}

// verify signs a fresh message with sk if s is nil, then checks the signature with the derived public key.
func verify(alg string, sk, msg, s []byte) error {
	a := sign.Alg(alg)
	var err error
	if s == nil {
		if s, err = sign.Sign(a, sk, msg); err != nil {
			return err
		}
	}
	pk, err := sign.Public(a, sk)
	if err != nil {
		return err
	}
	if err := sign.Verify(a, pk, msg, s); err != nil {
		return err
	}
	return expect(sign.Verify(a, pk, append(bytes.Clone(msg), 0), s) != nil, "altered message verified")
}

func roundTripSig(alg string) error {
	_, sk, err := sign.GenerateKey(sign.Alg(alg))
	if err != nil {
		return err
	}
	return verify(alg, sk, []byte("mainecoon kat"), nil)
}

func roundTripKEM(alg kem.Alg) error {
	pk, sk, err := kem.GenerateKey(alg)
	if err != nil {
		return err
	}
	ct, ss, err := kem.Encapsulate(alg, pk)
	if err != nil {
		return err
	}
	ss2, err := kem.Decapsulate(alg, sk, ct)
	return eq(ss2, err, ss)
}

// dhkem decapsulates a published RFC 9180 enc with skRm, then runs an encap round trip.
func dhkem(alg kem.Alg, skRm, enc, ss []byte) func() error {
	return func() error {
		got, err := kem.Decapsulate(alg, skRm, enc)
		if err := eq(got, err, ss); err != nil {
			return err
		}
		return roundTripKEM(alg)
	}
}

// gcmSealed is GCM spec test case 16 in aead's nonce ‖ ciphertext ‖ tag form.
func gcmSealed() []byte { return append(append(append([]byte{}, gcmNonce...), gcmCT...), gcmTag...) }

type oaepVec struct{ Sk, Ct, Msg, Label hx }

func oaepDecrypt(alg rsaoaep.Alg, x *oaepVec) func() error {
	return func() error {
		pt, err := rsaoaep.Decrypt(alg, x.Sk, x.Ct, x.Label)
		if err := eq(pt, err, x.Msg); err != nil {
			return err
		}
		bad := bytes.Clone(x.Ct)
		bad[len(bad)-1] ^= 1
		_, err = rsaoaep.Decrypt(alg, x.Sk, bad, x.Label)
		return expect(errors.Is(err, errors.ErrDecryptionFailed), "altered ciphertext decrypted")
	}
}

// sigVerify checks a published signature and that an altered one is rejected.
func sigVerify(alg sign.Alg, vec func() (pk, msg, s []byte)) func() error {
	return func() error {
		pk, msg, s := vec()
		if err := sign.Verify(alg, pk, msg, s); err != nil {
			return fmt.Errorf("published signature rejected: %v", err)
		}
		bad := bytes.Clone(s)
		bad[len(bad)/2] ^= 1
		return expect(sign.Verify(alg, pk, msg, bad) != nil, "altered signature verified")
	}
}

func hpkeRoundTrip(alg hpke.Alg) func() error {
	return func() error {
		pk, sk, err := hpke.GenerateKey(alg)
		if err != nil {
			return err
		}
		ct, err := hpke.Encrypt(alg, pk, []byte("kat"), []byte("aad"))
		if err != nil {
			return err
		}
		pt, err := hpke.Decrypt(alg, sk, ct, []byte("aad"))
		if err := eq(pt, err, []byte("kat")); err != nil {
			return err
		}
		_, err = hpke.Decrypt(alg, sk, ct, []byte("aaD"))
		return expect(errors.Is(err, errors.ErrDecryptionFailed), "aad not bound")
	}
}
