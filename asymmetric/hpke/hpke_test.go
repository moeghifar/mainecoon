package hpke

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// RFC 9180 test vectors, DHKEM(P-256) and DHKEM(X25519) with HKDF-SHA256/AES-256-GCM, base mode: open the first message
// with the published info, enc and skRm.
func TestRFC9180(t *testing.T) {
	var vs []struct {
		KemID       int `json:"kem_id"`
		KdfID       int `json:"kdf_id"`
		AeadID      int `json:"aead_id"`
		Info, SkRm  vectors.Hex
		Enc         vectors.Hex
		Encryptions []struct{ Aad, Ct, Pt vectors.Hex }
	}
	vectors.Load(t, "testdata/rfc9180.json", &vs)
	n := 0
	for _, v := range vs {
		alg := map[int]Alg{0x10: Classic, 0x20: X25519}[v.KemID]
		if alg == "" || v.KdfID != 1 || v.AeadID != 2 {
			continue
		}
		e := v.Encryptions[0]
		pt, err := decrypt(alg, v.SkRm, v.Info, append(bytes.Clone(v.Enc), e.Ct...), e.Aad)
		if err != nil || !bytes.Equal(pt, e.Pt) {
			t.Fatalf("open: %v", err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("vector not found (%d)", n)
	}
}

// UT-KEM-007, 008, 009.
func TestSuites(t *testing.T) {
	for _, alg := range []Alg{Classic, Hybrid, XWing, X25519, MLKEM768, MLKEM1024} {
		pk, sk, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(alg, err)
		}
		if p, _ := Public(alg, sk); !bytes.Equal(p, pk) {
			t.Fatal(alg, "Public(sk)")
		}
		ct, err := Encrypt(alg, pk, []byte("hello"), []byte("aad"))
		if err != nil || len(ct) != suites[string(alg)].encSize+5+16 {
			t.Fatal(alg, err, len(ct))
		}
		if pt, err := Decrypt(alg, sk, ct, []byte("aad")); err != nil || string(pt) != "hello" {
			t.Fatal(alg, "round trip", err)
		}
		_, sk2, _ := GenerateKey(alg)
		bad := bytes.Clone(ct)
		bad[len(bad)-1] ^= 1
		for name, c := range map[string]struct{ sk, ct, aad []byte }{
			"other key": {sk2, ct, []byte("aad")},
			"aad":       {sk, ct, []byte("aaD")},
			"tamper":    {sk, bad, []byte("aad")},
		} {
			if _, err := Decrypt(alg, c.sk, c.ct, c.aad); !errors.Is(err, errors.ErrDecryptionFailed) {
				t.Fatal(alg, name, err)
			}
		}
		if _, err := Decrypt(alg, sk, ct[:10], nil); !errors.Is(err, errors.ErrCiphertextEmpty) {
			t.Fatal(alg, "short ciphertext", err)
		}
	}
}
