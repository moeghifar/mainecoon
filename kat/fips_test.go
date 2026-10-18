package kat

import (
	"bytes"
	"crypto/fips140"
	"testing"

	"github.com/moeghifar/mainecoon/asymmetric/hpke"
	"github.com/moeghifar/mainecoon/asymmetric/kem"
	"github.com/moeghifar/mainecoon/asymmetric/rsaoaep"
	"github.com/moeghifar/mainecoon/asymmetric/sign"
	"github.com/moeghifar/mainecoon/drbg"
	"github.com/moeghifar/mainecoon/hash"
	"github.com/moeghifar/mainecoon/kdf"
	"github.com/moeghifar/mainecoon/mac"
	"github.com/moeghifar/mainecoon/symmetric/aead"
	"github.com/moeghifar/mainecoon/symmetric/gmac"
)

// Run with GODEBUG=fips140=only: every FIPS-approved algorithm that mainecoon takes from
// the Go stdlib must work using only the Go FIPS 140-3 module. (tink-go, capitalone/fpe and
// circl primitives are outside the module and are not expected to run here.)
func TestFIPSOnlyModule(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("set GODEBUG=fips140=only")
	}
	key, err := drbg.Bytes(32)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := aead.Encrypt(aead.AES256GCM, key, []byte("x"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := aead.Decrypt(aead.AES256GCM, key, ct, []byte("c")); err != nil || !bytes.Equal(pt, []byte("x")) {
		t.Fatal("AES-256-GCM", err)
	}
	tag, err := gmac.Sum(key, []byte("m"))
	if err != nil || gmac.Verify(key, []byte("m"), tag) != nil {
		t.Fatal("GMAC", err)
	}
	for _, alg := range []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"} {
		if _, err := hash.Sum(alg, []byte("abc")); err != nil {
			t.Fatal(alg, err)
		}
	}
	for _, alg := range []string{"HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"} {
		if _, err := mac.Sum(alg, bytes.Repeat([]byte{1}, 64), []byte("m")); err != nil {
			t.Fatal(alg, err)
		}
	}
	if _, err := kdf.Derive("HKDF-SHA256", key, nil, []byte("i"), 32); err != nil {
		t.Fatal("HKDF", err)
	}
	for _, alg := range []sign.Alg{sign.ECDSAP256, sign.ECDSAP384, sign.ECDSAP521, sign.Ed25519, sign.RSAPSS2048, sign.RSAPSS3072, sign.MLDSA44, sign.MLDSA65, sign.MLDSA87} {
		pk, sk, err := sign.GenerateKey(alg)
		if err != nil {
			t.Fatal(alg, err)
		}
		s, err := sign.Sign(alg, sk, []byte("m"))
		if err != nil || sign.Verify(alg, pk, []byte("m"), s) != nil {
			t.Fatal(alg, err)
		}
	}
	for _, alg := range []kem.Alg{kem.MLKEM768, kem.MLKEM1024} {
		if err := roundTripKEM(alg); err != nil {
			t.Fatal(alg, err)
		}
	}
	pk, sk, err := rsaoaep.GenerateKey(rsaoaep.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if ct, err := rsaoaep.Encrypt(rsaoaep.RSA2048, pk, key, nil); err != nil {
		t.Fatal("RSA-OAEP", err)
	} else if got, err := rsaoaep.Decrypt(rsaoaep.RSA2048, sk, ct, nil); err != nil || !bytes.Equal(got, key) {
		t.Fatal("RSA-OAEP", err)
	}
	for _, alg := range []hpke.Alg{hpke.Classic, hpke.Hybrid} {
		pk, sk, err := hpke.GenerateKey(alg)
		if err != nil {
			t.Fatal(alg, err)
		}
		ct, err := hpke.Encrypt(alg, pk, []byte("x"), nil)
		if err != nil {
			t.Fatal(alg, err)
		}
		if pt, err := hpke.Decrypt(alg, sk, ct, nil); err != nil || !bytes.Equal(pt, []byte("x")) {
			t.Fatal(alg, err)
		}
	}
}
