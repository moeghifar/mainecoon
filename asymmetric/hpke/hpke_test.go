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

// RFC 9180 Appendix A test vectors (base mode, DHKEM(P-256) and DHKEM(X25519), HKDF-SHA256,
// AES-256-GCM): every exported value, derived from the published enc and skRm.
func TestRFC9180Export(t *testing.T) {
	var vs []struct {
		KemID      int `json:"kem_id"`
		KdfID      int `json:"kdf_id"`
		AeadID     int `json:"aead_id"`
		Info, SkRm vectors.Hex
		Enc        vectors.Hex
		Exports    []struct {
			Ctx vectors.Hex `json:"exporter_context"`
			L   int
			Out vectors.Hex `json:"exported_value"`
		}
	}
	vectors.Load(t, "testdata/rfc9180.json", &vs)
	n := 0
	for _, v := range vs {
		alg := map[int]Alg{0x10: Classic, 0x20: X25519}[v.KemID]
		if alg == "" || v.KdfID != 1 || v.AeadID != 2 {
			continue
		}
		for _, e := range v.Exports {
			got, err := ReceiverExport(alg, v.SkRm, v.Enc, v.Info, e.Ctx, e.L)
			if err != nil || !bytes.Equal(got, e.Out) {
				t.Fatalf("%s export %x: %v", alg, e.Ctx, err)
			}
			n++
		}
	}
	if n != 6 {
		t.Fatalf("vectors not found (%d)", n)
	}
}

func TestWithInfoAndExport(t *testing.T) {
	info, ctx := []byte("cryptop/v1"), []byte("ctx")
	for _, tc := range []struct {
		alg Alg
		nh  int
	}{{Classic, 32}, {Hybrid, 48}, {XWing, 32}, {X25519, 32}, {MLKEM768, 32}, {MLKEM1024, 48}} {
		alg := tc.alg
		pk, sk, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(alg, err)
		}
		ct, err := EncryptWithInfo(alg, pk, info, []byte("hello"), []byte("aad"))
		if err != nil {
			t.Fatal(alg, err)
		}
		if pt, err := DecryptWithInfo(alg, sk, info, ct, []byte("aad")); err != nil || string(pt) != "hello" {
			t.Fatal(alg, "with info round trip", err)
		}
		for name, in := range map[string][]byte{"wrong info": []byte("other"), "default info": []byte(Info)} {
			if _, err := DecryptWithInfo(alg, sk, in, ct, []byte("aad")); !errors.Is(err, errors.ErrDecryptionFailed) {
				t.Fatal(alg, name, err)
			}
		}

		enc, s1, err := SenderExport(alg, pk, info, ctx, tc.nh*255)
		if err != nil || len(s1) != tc.nh*255 {
			t.Fatal(alg, "sender export", err)
		}
		s2, err := ReceiverExport(alg, sk, enc, info, ctx, tc.nh*255)
		if err != nil || !bytes.Equal(s1, s2) {
			t.Fatal(alg, "receiver export", err)
		}
		if s3, _ := ReceiverExport(alg, sk, enc, []byte("other"), ctx, tc.nh*255); bytes.Equal(s1, s3) {
			t.Fatal(alg, "wrong info exported same secret")
		}
		if s3, _ := ReceiverExport(alg, sk, enc, info, []byte("other"), tc.nh*255); bytes.Equal(s1, s3) {
			t.Fatal(alg, "wrong context exported same secret")
		}

		for name, c := range map[string]struct {
			sk, enc []byte
			l       int
			want    error
		}{
			"L zero":      {sk, enc, 0, errors.ErrInputInvalid},
			"L too large": {sk, enc, tc.nh*255 + 1, errors.ErrInputInvalid},
			"short enc":   {sk, enc[:len(enc)-1], 32, errors.ErrInputInvalid},
			"bad sk":      {sk[:3], enc, 32, errors.ErrKeyFormatInvalid},
		} {
			if _, err := ReceiverExport(alg, c.sk, c.enc, info, ctx, c.l); !errors.Is(err, c.want) {
				t.Fatal(alg, name, err)
			}
		}
		if _, _, err := SenderExport(alg, pk, info, ctx, tc.nh*255+1); !errors.Is(err, errors.ErrInputInvalid) {
			t.Fatal(alg, "sender L too large", err)
		}
		if _, _, err := SenderExport(alg, pk[:3], info, ctx, 32); !errors.Is(err, errors.ErrKeyFormatInvalid) {
			t.Fatal(alg, "sender bad pk", err)
		}
	}
}
