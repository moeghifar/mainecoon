package rsaoaep

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// C2SP Wycheproof rsa_oaep_{2048,3072,4096}_sha256_mgf1sha256_test.json: every valid vector
// decrypts to msg, every invalid one fails with ErrDecryptionFailed.
func TestWycheproof(t *testing.T) {
	for alg, path := range map[Alg]string{
		RSA2048: "testdata/rsa_oaep_2048_sha256_mgf1sha256_test.json",
		RSA3072: "testdata/rsa_oaep_3072_sha256_mgf1sha256_test.json",
		RSA4096: "testdata/rsa_oaep_4096_sha256_mgf1sha256_test.json",
	} {
		var f struct {
			TestGroups []struct {
				PrivateKeyPkcs8 vectors.Hex
				Tests           []struct {
					TcID           int `json:"tcId"`
					Msg, Ct, Label vectors.Hex
					Result         string
				}
			}
		}
		vectors.Load(t, path, &f)
		n := 0
		for _, g := range f.TestGroups {
			for _, tc := range g.Tests {
				if tc.Result == "acceptable" {
					continue
				}
				pt, err := Decrypt(alg, g.PrivateKeyPkcs8, tc.Ct, tc.Label)
				ok := err == nil && bytes.Equal(pt, tc.Msg)
				if ok != (tc.Result == "valid") {
					t.Errorf("%s tc %d: ok=%v result=%s err=%v", alg, tc.TcID, ok, tc.Result, err)
				}
				if tc.Result == "invalid" && err != nil && !errors.Is(err, errors.ErrDecryptionFailed) {
					t.Errorf("%s tc %d: error %v leaks a reason", alg, tc.TcID, err)
				}
				n++
			}
		}
		if n < 20 {
			t.Fatalf("%s: only %d vectors", alg, n)
		}
	}
}

func TestRoundTripAndRejects(t *testing.T) {
	pk, sk, err := GenerateKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Public(RSA2048, sk); err != nil || !bytes.Equal(p, pk) {
		t.Fatal("Public", err)
	}
	dek := bytes.Repeat([]byte{7}, 32)
	ct, err := Encrypt(RSA2048, pk, dek, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decrypt(RSA2048, sk, ct, []byte("ctx")); err != nil || !bytes.Equal(got, dek) {
		t.Fatal("round trip", err)
	}
	if _, err := Decrypt(RSA2048, sk, ct, []byte("ctY")); !errors.Is(err, errors.ErrDecryptionFailed) {
		t.Fatal("label not bound", err)
	}
	if _, err := Encrypt(RSA2048, pk, make([]byte, 191), nil); !errors.Is(err, errors.ErrInputTooLarge) {
		t.Fatal("oversized plaintext", err)
	}
	if _, err := Encrypt(RSA3072, pk, dek, nil); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("2048-bit key accepted as 3072", err)
	}
	if _, _, err := GenerateKey("RSA-PKCS1-v1.5"); !errors.Is(err, errors.ErrAlgorithmDisabled) {
		t.Fatal("PKCS#1 v1.5", err)
	}
}
