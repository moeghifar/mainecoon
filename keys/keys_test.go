package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/moeghifar/mainecoon/asymmetric/kem"
	"github.com/moeghifar/mainecoon/asymmetric/rsaoaep"
	"github.com/moeghifar/mainecoon/asymmetric/sign"
	"github.com/moeghifar/mainecoon/errors"
)

func gen(t *testing.T, alg string) (pk, sk []byte) {
	t.Helper()
	pk, sk, err := sign.GenerateKey(sign.Alg(alg))
	if err != nil {
		pk, sk, err = kem.GenerateKey(kem.Alg(alg))
	}
	if err != nil {
		pk, sk, err = rsaoaep.GenerateKey(rsaoaep.Alg(alg))
	}
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestRoundTrips(t *testing.T) {
	for alg, fs := range map[string][]Format{
		"ECDSA-P256": {RawHex, RawBase64, PEM, JWK}, "ECDSA-P384": {PEM, JWK}, "Ed25519": {PEM, JWK},
		"RSA-PSS-3072": {PEM, JWK}, "ML-DSA-65": {PEM, JWK}, "ML-DSA-87": {PEM, JWK}, "SLH-DSA-SHA2-128s": {JWK},
		"ECDH-P256": {PEM, JWK}, "ECDH-P384": {PEM, JWK}, "X25519": {PEM, JWK}, "ML-KEM-768": {JWK}, "ML-KEM-1024": {JWK},
		"ECDSA-P521": {PEM, JWK}, "ECDH-P521": {PEM, JWK}, "Ed448": {JWK}, "ML-DSA-44": {PEM, JWK}, "ML-KEM-512": {JWK},
		"X-Wing": {JWK}, "RSA-PSS-2048": {PEM, JWK}, "RSA-OAEP-2048": {PEM, JWK},
	} {
		pk, sk := gen(t, alg)
		for _, f := range fs {
			for _, c := range []struct {
				raw     []byte
				private bool
			}{{pk, false}, {sk, true}} {
				s, err := Encode(alg, c.raw, c.private, f)
				if err != nil {
					t.Fatalf("%s %s private=%v encode: %v", alg, f, c.private, err)
				}
				back, err := Decode(alg, s, c.private, f)
				if err != nil || string(back) != string(c.raw) {
					t.Fatalf("%s %s private=%v decode: %v", alg, f, c.private, err)
				}
			}
		}
	}
}

// Keys from other tools (here: crypto/x509 directly, as OpenSSL would write them) decode.
func TestForeignPEM(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	raw, err := Decode("ECDSA-P256", p, true, PEM)
	want, _ := k.Bytes()
	if err != nil || string(raw) != string(want) {
		t.Fatal(err)
	}
	if _, err := Decode("ECDSA-P384", p, true, PEM); !errors.Is(err, errors.ErrKeyFormatInvalid) {
		t.Fatal("P-256 key accepted as P-384")
	}
	if _, err := Decode("ECDSA-P256", p, false, PEM); !errors.Is(err, errors.ErrKeyFormatInvalid) {
		t.Fatal("private PEM accepted as public")
	}
}

func TestJWKShape(t *testing.T) {
	pk, sk := gen(t, "Ed25519")
	s, _ := Encode("Ed25519", sk, true, JWK)
	var j map[string]string
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		t.Fatal(err)
	}
	if j["kty"] != "OKP" || j["crv"] != "Ed25519" || j["d"] == "" || j["x"] == "" {
		t.Fatalf("RFC 8037 shape: %s", s)
	}
	// A private JWK whose public part belongs to another key is rejected.
	other, _ := gen(t, "Ed25519")
	j["x"] = strings.TrimRight(b64.EncodeToString(other), "=")
	bad, _ := json.Marshal(j)
	if _, err := Decode("Ed25519", string(bad), true, JWK); !errors.Is(err, errors.ErrKeyFormatInvalid) {
		t.Fatal("mismatched JWK accepted")
	}
	_ = pk
	r, _ := Encode("RSA-PSS-3072", mustRSA(t), true, JWK)
	var rj map[string]string
	if err := json.Unmarshal([]byte(r), &rj); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"n", "e", "d", "p", "q", "dp", "dq", "qi"} {
		if rj[f] == "" {
			t.Fatalf("RSA JWK lacks %s", f)
		}
	}
}

func mustRSA(t *testing.T) []byte { _, sk := gen(t, "RSA-PSS-3072"); return sk }

func TestUnsupported(t *testing.T) {
	_, sk := gen(t, "ML-KEM-768")
	if _, err := Encode("ML-KEM-768", sk, true, PEM); !errors.Is(err, errors.ErrKeyFormatInvalid) {
		t.Fatal("ML-KEM PEM")
	}
	if _, err := Encode("ECDSA-P256", sk, true, "XML"); !errors.Is(err, errors.ErrKeyFormatInvalid) {
		t.Fatal("unknown format")
	}
	if _, err := Decode("ECDSA-P256", "zz", true, RawHex); !errors.Is(err, errors.ErrKeyFormatInvalid) {
		t.Fatal("bad hex")
	}
}

func FuzzDecode(f *testing.F) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	f.Add(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), uint8(0))
	f.Add(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`, uint8(1))
	f.Add(`{"kty":"AKP","alg":"ML-DSA-65","pub":"AA"}`, uint8(2))
	algs := []string{"ECDSA-P256", "RSA-PSS-3072", "ML-DSA-65", "Ed25519", "X25519", "ML-KEM-768"}
	f.Fuzz(func(t *testing.T, s string, a uint8) {
		alg := algs[int(a)%len(algs)]
		for _, fm := range []Format{PEM, JWK} {
			_, _ = Decode(alg, s, false, fm)
			_, _ = Decode(alg, s, true, fm)
		}
	})
}

// A huge fake RSA JWK must be rejected by size before any expensive validation.
func TestRSAJWKSizeBeforeWork(t *testing.T) {
	big := b64.EncodeToString(append([]byte{0x80}, make([]byte, 8191)...)) // 65536-bit modulus
	j := `{"kty":"RSA","n":"` + big + `","e":"AQAB","d":"` + big + `","p":"` + big + `","q":"` + big + `"}`
	start := time.Now()
	if _, err := Decode("RSA-PSS-3072", j, true, JWK); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("oversized RSA JWK:", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("rejection took %v", d)
	}
	tiny := b64.EncodeToString(append([]byte{0x80}, make([]byte, 127)...))  // 1024-bit
	small := b64.EncodeToString(append([]byte{0x80}, make([]byte, 255)...)) // 2048-bit
	if _, err := Decode("RSA-PSS-3072", `{"kty":"RSA","n":"`+tiny+`","e":"AQAB"}`, false, JWK); !errors.Is(err, errors.ErrKeyTooShort) {
		t.Fatal("1024-bit RSA JWK:", err)
	}
	if _, err := Decode("RSA-PSS-3072", `{"kty":"RSA","n":"`+small+`","e":"AQAB"}`, false, JWK); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("2048-bit RSA JWK:", err)
	}
}
