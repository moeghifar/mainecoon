package kem

import (
	"bytes"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

var all = []Alg{ECDHP256, ECDHP384, ECDHP521, X25519, MLKEM512, MLKEM768, MLKEM1024, XWing, X25519MLKEM768}

// UT-KEM-001, 003, 004 for every scheme.
func TestAllSchemes(t *testing.T) {
	for _, alg := range all {
		pk, sk, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(alg, err)
		}
		if p, err := Public(alg, sk); err != nil || !bytes.Equal(p, pk) {
			t.Fatal(alg, "Public(sk)", err)
		}
		ct, ss, err := Encapsulate(alg, pk)
		if err != nil {
			t.Fatal(alg, err)
		}
		if ss2, err := Decapsulate(alg, sk, ct); err != nil || !bytes.Equal(ss, ss2) || len(ss) < 32 {
			t.Fatal(alg, "round trip", err)
		}
		_, sk2, _ := GenerateKey(alg)
		if ss3, err := Decapsulate(alg, sk2, ct); err == nil && bytes.Equal(ss3, ss) {
			t.Fatal(alg, "wrong key gave the same secret")
		}
		bad := bytes.Clone(ct)
		bad[0] ^= 1
		if ss4, err := Decapsulate(alg, sk, bad); err == nil && bytes.Equal(ss4, ss) {
			t.Fatal(alg, "tampered ciphertext gave the same secret")
		}
		if _, err := Decapsulate(alg, sk, ct[:len(ct)-1]); !errors.Is(err, errors.ErrDecapsulationFailed) {
			t.Fatal(alg, "short ciphertext", err)
		}
		if _, _, err := Encapsulate(alg, pk[:len(pk)-1]); !errors.Is(err, errors.ErrKeyFormatInvalid) {
			t.Fatal(alg, "short public key", err)
		}
	}
}

// RFC 9180 test vectors, base mode, DHKEM(P-256), DHKEM(P-521) and DHKEM(X25519)
// (from circl's copy of the CFRG vectors file): encapsulation with the published ikmE gives
// the published enc and shared_secret; decapsulation with skRm recovers it. UT-KEM-002.
func TestRFC9180(t *testing.T) {
	var vs []struct {
		KemID                 int `json:"kem_id"`
		IkmE, PkRm, SkRm, Enc vectors.Hex
		SharedSecret          vectors.Hex `json:"shared_secret"`
	}
	vectors.Load(t, "testdata/rfc9180_dhkem.json", &vs)
	ids := map[int]Alg{0x10: ECDHP256, 0x12: ECDHP521, 0x20: X25519}
	for _, v := range vs {
		alg := ids[v.KemID]
		c := schemes[string(alg)].(circlScheme)
		pk, err := c.s.UnmarshalBinaryPublicKey(v.PkRm)
		if err != nil {
			t.Fatal(alg, err)
		}
		enc, ss, err := c.s.EncapsulateDeterministically(pk, v.IkmE)
		if err != nil || !bytes.Equal(enc, v.Enc) || !bytes.Equal(ss, v.SharedSecret) {
			t.Errorf("%s: encap mismatch", alg)
		}
		if got, err := Decapsulate(alg, v.SkRm, v.Enc); err != nil || !bytes.Equal(got, v.SharedSecret) {
			t.Errorf("%s: decap mismatch %v", alg, err)
		}
	}
	if len(vs) < 10 {
		t.Fatalf("only %d vectors", len(vs))
	}
}

// UT-KEM-004: ML-KEM implicit rejection returns a secret, not an error.
func TestImplicitRejection(t *testing.T) {
	pk, sk, _ := GenerateKey(MLKEM768)
	ct, ss, _ := Encapsulate(MLKEM768, pk)
	ct[10] ^= 0xff
	if got, err := Decapsulate(MLKEM768, sk, ct); err != nil || len(got) != 32 || bytes.Equal(got, ss) {
		t.Fatal("implicit rejection broken", err)
	}
}

// NIST ACVP ML-KEM keyGen and encapsulation (FIPS 203), derandomised with mlkemtest.
func TestACVPMLKEM(t *testing.T) {
	var f struct {
		KeyGen []struct {
			ParameterSet string
			Tests        []struct {
				TcID     int `json:"tcId"`
				D, Z, Ek vectors.Hex
			}
		}
		Encap []struct {
			ParameterSet string
			Tests        []struct {
				TcID        int `json:"tcId"`
				Ek, M, C, K vectors.Hex
			}
		}
	}
	vectors.Load(t, "testdata/acvp_mlkem.json", &f)
	n := 0
	for _, g := range f.KeyGen {
		for _, tc := range g.Tests {
			pk, err := Public(Alg(g.ParameterSet), append(bytes.Clone(tc.D), tc.Z...))
			if err != nil || !bytes.Equal(pk, tc.Ek) {
				t.Errorf("%s keyGen tc %d", g.ParameterSet, tc.TcID)
			}
			n++
		}
	}
	for _, g := range f.Encap {
		for _, tc := range g.Tests {
			var k, c []byte
			var err error
			if g.ParameterSet == "ML-KEM-768" {
				ek, _ := mlkem.NewEncapsulationKey768(tc.Ek)
				k, c, err = mlkemtest.Encapsulate768(ek, tc.M)
			} else {
				ek, _ := mlkem.NewEncapsulationKey1024(tc.Ek)
				k, c, err = mlkemtest.Encapsulate1024(ek, tc.M)
			}
			if err != nil || !bytes.Equal(k, tc.K) || !bytes.Equal(c, tc.C) {
				t.Errorf("%s encap tc %d", g.ParameterSet, tc.TcID)
			}
			n++
		}
	}
	if n < 20 {
		t.Fatalf("only %d vectors", n)
	}
}

// Removed schemes.
func TestRejected(t *testing.T) {
	if _, _, err := GenerateKey("ECDH-P256+ML-KEM-768"); !errors.Is(err, errors.ErrAlgorithmDisabled) {
		t.Fatal("old own hybrid still accepted", err)
	}
}

// X-Wing (draft-connolly-cfrg-xwing-kem): regenerate the spec's test-vectors.txt (3 vectors from
// a SHAKE128 stream, as in the draft's reference generator) through this package and compare its
// SHAKE128 digest with the value published for the spec file.
func TestXWingSpecVectors(t *testing.T) {
	h := sha3.NewSHAKE128()
	w := new(bytes.Buffer)
	hexLine := func(prefix string, val []byte) {
		const indent, width = "  ", 74
		s := hex.EncodeToString(val)
		if len(prefix)+len(s)+5 < width {
			fmt.Fprintf(w, "%s     %s\n", prefix, s)
			return
		}
		fmt.Fprintf(w, "%s\n", prefix)
		for len(s) != 0 {
			n := min(len(s), width-len(indent))
			fmt.Fprintf(w, "%s%s\n", indent, s[:n])
			s = s[n:]
		}
	}
	c := schemes[string(XWing)].(circlScheme).s
	for i := 0; i < 3; i++ {
		seed := make([]byte, 32)
		h.Read(seed)
		hexLine("seed", seed)
		pk, err := Public(XWing, seed)
		if err != nil {
			t.Fatal(err)
		}
		hexLine("sk", seed)
		hexLine("pk", pk)
		eseed := make([]byte, 64)
		h.Read(eseed)
		hexLine("eseed", eseed)
		pko, _ := c.UnmarshalBinaryPublicKey(pk)
		ct, ss, err := c.EncapsulateDeterministically(pko, eseed)
		if err != nil {
			t.Fatal(err)
		}
		hexLine("ct", ct)
		hexLine("ss", ss)
		if got, err := Decapsulate(XWing, seed, ct); err != nil || !bytes.Equal(got, ss) {
			t.Fatal("decapsulate", err)
		}
		fmt.Fprintf(w, "\n")
	}
	d := sha3.NewSHAKE128()
	d.Write(w.Bytes())
	sum := make([]byte, 32)
	d.Read(sum)
	if got := hex.EncodeToString(sum); got != "1bcd0057d861d6b866239936cadcaeee1ec0164dedc181c386e9e54fe46156fe" {
		t.Fatalf("X-Wing vectors digest %s", got)
	}
}

// C2SP Wycheproof mlkem_512_keygen_seed_test.json and mlkem_512_test.json.
func TestWycheproofMLKEM512(t *testing.T) {
	var kg struct {
		TestGroups []struct {
			Tests []struct {
				TcID     int `json:"tcId"`
				Seed, Ek vectors.Hex
				Result   string
			}
		}
	}
	vectors.Load(t, "testdata/mlkem_512_keygen_seed_test.json", &kg)
	n := 0
	for _, g := range kg.TestGroups {
		for _, tc := range g.Tests {
			pk, err := Public(MLKEM512, tc.Seed)
			if ok := err == nil && bytes.Equal(pk, tc.Ek); ok != (tc.Result == "valid") {
				t.Errorf("keygen tc %d: ok=%v %s", tc.TcID, ok, tc.Result)
			}
			n++
		}
	}
	var dc struct {
		TestGroups []struct {
			Tests []struct {
				TcID           int `json:"tcId"`
				Seed, Ek, C, K vectors.Hex
				Result         string
			}
		}
	}
	vectors.Load(t, "testdata/mlkem_512_test.json", &dc)
	for _, g := range dc.TestGroups {
		for _, tc := range g.Tests {
			pk, err := Public(MLKEM512, tc.Seed)
			if err != nil || !bytes.Equal(pk, tc.Ek) {
				if tc.Result == "valid" {
					t.Errorf("decaps tc %d: key mismatch", tc.TcID)
				}
				continue
			}
			k, err := Decapsulate(MLKEM512, tc.Seed, tc.C)
			if ok := err == nil && bytes.Equal(k, tc.K); ok != (tc.Result == "valid") {
				t.Errorf("decaps tc %d: ok=%v %s", tc.TcID, ok, tc.Result)
			}
			n++
		}
	}
	if n < 20 {
		t.Fatalf("only %d vectors", n)
	}
}
