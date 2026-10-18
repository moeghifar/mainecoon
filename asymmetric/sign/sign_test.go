package sign

import (
	"bytes"
	"crypto/mldsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// UT-SIG-001..003, 005, 007, 010, 011, 013 for every scheme.
func TestAllSchemes(t *testing.T) {
	msg := []byte("peruri sandi")
	for _, alg := range []Alg{ECDSAP256, ECDSAP384, ECDSAP521, Ed25519, Ed448, RSAPSS2048, RSAPSS3072, RSAPSS4096, MLDSA44, MLDSA65, MLDSA87, SLHDSASHA2128s} {
		pk, sk, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(alg, err)
		}
		if derived, err := Public(alg, sk); err != nil || !bytes.Equal(derived, pk) {
			t.Fatal(alg, "Public(sk) differs from generated pk", err)
		}
		s, err := Sign(alg, sk, msg)
		if err != nil {
			t.Fatal(alg, err)
		}
		if err := Verify(alg, pk, msg, s); err != nil {
			t.Fatal(alg, "valid signature rejected", err)
		}
		bad := bytes.Clone(s)
		bad[len(bad)/2] ^= 1
		if !errors.Is(Verify(alg, pk, msg, bad), errors.ErrVerificationFailed) {
			t.Fatal(alg, "tampered signature verified")
		}
		if !errors.Is(Verify(alg, pk, []byte("peruri sandI"), s), errors.ErrVerificationFailed) {
			t.Fatal(alg, "tampered message verified")
		}
		pk2, _, _ := GenerateKey(alg)
		if !errors.Is(Verify(alg, pk2, msg, s), errors.ErrVerificationFailed) {
			t.Fatal(alg, "wrong key verified")
		}
	}
}

// RFC 6979 A.2.5: P-256, SHA-256, message "sample". Deterministic per the VAPT note.
func TestRFC6979(t *testing.T) {
	sk := vectors.MustHex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	s, err := Sign("ECDSA-P256", sk, []byte("sample"))
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(s, &rs); err != nil {
		t.Fatal(err)
	}
	if rs.R.Text(16) != "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" ||
		rs.S.Text(16) != "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8" {
		t.Fatalf("r=%x s=%x", rs.R, rs.S)
	}
	again, _ := Sign("ECDSA-P256", sk, []byte("sample"))
	if !bytes.Equal(s, again) {
		t.Fatal("not deterministic")
	}
}

// RFC 8032 section 7.1 test 1.
func TestEd25519Vector(t *testing.T) {
	s, _ := Sign("Ed25519", vectors.MustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), nil)
	if !bytes.Equal(s, vectors.MustHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")) {
		t.Fatal("signature mismatch")
	}
}

type pqVec struct {
	KeyGen []struct {
		ParameterSet string
		Tests        []struct {
			TcID     int `json:"tcId"`
			Seed, Pk vectors.Hex
		}
	}
	SigVer []struct {
		ParameterSet string
		Tests        []struct {
			TcID                            int `json:"tcId"`
			Pk, Message, Context, Signature vectors.Hex
			TestPassed                      bool
		}
	}
}

// FIPS 204 ACVP keyGen (seed -> public key) and sigVer (with context, incl. invalid cases).
func TestACVPMLDSA(t *testing.T) {
	var f pqVec
	vectors.Load(t, "testdata/acvp_mldsa.json", &f)
	params := map[string]mldsa.Parameters{"ML-DSA-65": mldsa.MLDSA65(), "ML-DSA-87": mldsa.MLDSA87()}
	n := 0
	for _, g := range f.KeyGen {
		for _, tc := range g.Tests {
			pk, err := schemes[g.ParameterSet].Public(tc.Seed)
			if err != nil || !bytes.Equal(pk, tc.Pk) {
				t.Errorf("%s keyGen tc %d", g.ParameterSet, tc.TcID)
			}
			n++
		}
	}
	for _, g := range f.SigVer {
		for _, tc := range g.Tests {
			pk, err := mldsa.NewPublicKey(params[g.ParameterSet], tc.Pk)
			ok := err == nil && mldsa.Verify(pk, tc.Message, tc.Signature, &mldsa.Options{Context: string(tc.Context)}) == nil
			if ok != tc.TestPassed {
				t.Errorf("%s sigVer tc %d: got %v want %v", g.ParameterSet, tc.TcID, ok, tc.TestPassed)
			}
			n++
		}
	}
	if n < 40 {
		t.Fatalf("only %d vectors", n)
	}
}

// FIPS 205 ACVP sigVer for SLH-DSA-SHA2-128s.
func TestACVPSLHDSA(t *testing.T) {
	var f pqVec
	vectors.Load(t, "testdata/acvp_slhdsa.json", &f)
	n := 0
	for _, g := range f.SigVer {
		for _, tc := range g.Tests {
			k := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
			ok := k.UnmarshalBinary(tc.Pk) == nil && slhdsa.Verify(&k, slhdsa.NewMessage(tc.Message), tc.Signature, tc.Context)
			if ok != tc.TestPassed {
				t.Errorf("tc %d: got %v want %v", tc.TcID, ok, tc.TestPassed)
			}
			n++
		}
	}
	if n < 10 {
		t.Fatalf("only %d vectors", n)
	}
}

// UT-SIG-008, 009 and below-floor IDs.
func TestRejected(t *testing.T) {
	for alg, want := range map[Alg]error{
		"RSA-PSS-1024":         errors.ErrParameterBelowFloor,
		"RSA-PKCS1-v1_5":       errors.ErrAlgorithmDisabled,
		"DSA":                  errors.ErrAlgorithmDisabled,
		"ECDSA-P256+ML-DSA-65": errors.ErrAlgorithmDisabled,
	} {
		if _, _, err := GenerateKey(alg); !errors.Is(err, want) {
			t.Errorf("%s: %v", alg, err)
		}
	}
	_, sk3072, _ := GenerateKey("RSA-PSS-3072")
	if _, err := Sign("RSA-PSS-4096", sk3072, nil); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("3072-bit key accepted as 4096")
	}
}

// C2SP Wycheproof rsa_pss_{3072,4096}_sha256_mgf1_32_test.json: RSASSA-PSS, SHA-256, MGF1-SHA-256,
// 32-byte salt (the parameters Sign uses).
func TestWycheproofRSAPSS(t *testing.T) {
	for alg, path := range map[Alg]string{
		RSAPSS3072: "testdata/wycheproof_rsa_pss_3072_sha256_mgf1_32.json",
		RSAPSS4096: "testdata/wycheproof_rsa_pss_4096_sha256_mgf1_32.json",
	} {
		var f struct {
			TestGroups []struct {
				PublicKeyDer vectors.Hex
				Tests        []struct {
					TcID     int `json:"tcId"`
					Msg, Sig vectors.Hex
					Result   string
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
				if ok := Verify(alg, g.PublicKeyDer, tc.Msg, tc.Sig) == nil; ok != (tc.Result == "valid") {
					t.Errorf("%s tc %d: ok=%v result=%s", alg, tc.TcID, ok, tc.Result)
				}
				n++
			}
		}
		if n < 20 {
			t.Fatalf("%s: only %d vectors", alg, n)
		}
	}
}

// C2SP Wycheproof: ecdsa_secp521r1_sha512_test.json (DER signatures), ed448_test.json and
// mldsa_44_verify_test.json. Every valid signature verifies, every invalid one is rejected.
func TestWycheproofNewSchemes(t *testing.T) {
	type tcase struct {
		TcID          int `json:"tcId"`
		Msg, Sig, Ctx vectors.Hex
		Result        string
	}
	run := func(alg Alg, pk []byte, tests []tcase) int {
		for _, tc := range tests {
			if tc.Result == "acceptable" || len(tc.Ctx) > 0 { // the API signs with an empty context
				continue
			}
			if ok := Verify(alg, pk, tc.Msg, tc.Sig) == nil; ok != (tc.Result == "valid") {
				t.Errorf("%s tc %d: ok=%v result=%s", alg, tc.TcID, ok, tc.Result)
			}
		}
		return len(tests)
	}
	var p521 struct {
		TestGroups []struct {
			PublicKey struct{ Uncompressed vectors.Hex }
			Tests     []tcase
		}
	}
	vectors.Load(t, "testdata/ecdsa_secp521r1_sha512_test.json", &p521)
	n := 0
	for _, g := range p521.TestGroups {
		n += run(ECDSAP521, g.PublicKey.Uncompressed, g.Tests)
	}
	var ed struct {
		TestGroups []struct {
			PublicKey struct{ Pk vectors.Hex }
			Tests     []tcase
		}
	}
	vectors.Load(t, "testdata/ed448_test.json", &ed)
	for _, g := range ed.TestGroups {
		n += run(Ed448, g.PublicKey.Pk, g.Tests)
	}
	var ml struct {
		TestGroups []struct {
			PublicKey vectors.Hex
			Tests     []tcase
		}
	}
	vectors.Load(t, "testdata/mldsa_44_verify_test.json", &ml)
	for _, g := range ml.TestGroups {
		n += run(MLDSA44, g.PublicKey, g.Tests)
	}
	if n < 200 {
		t.Fatalf("only %d vectors", n)
	}
}
