package kdf

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// RFC 5869 test case 1. UT-KDF-001, 002, 003.
func TestHKDF(t *testing.T) {
	ikm := vectors.MustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := vectors.MustHex("000102030405060708090a0b0c")
	info := vectors.MustHex("f0f1f2f3f4f5f6f7f8f9")
	got, err := Derive("HKDF-SHA256", ikm, salt, info, 42)
	if err != nil || !bytes.Equal(got, vectors.MustHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")) {
		t.Fatalf("RFC 5869 TV1: %x %v", got, err)
	}
	other, _ := Derive("HKDF-SHA256", ikm, salt, []byte("other"), 42)
	if bytes.Equal(got, other) {
		t.Fatal("info binding broken")
	}
}

// C2SP Wycheproof hkdf_sha384_test.json and hkdf_sha512_test.json, inside the library's
// bounds (ikm ≥ 16 bytes, 16..512 output bytes).
func TestWycheproof(t *testing.T) {
	for alg, path := range map[string]string{
		"HKDF-SHA384": "testdata/wycheproof_hkdf_sha384.json",
		"HKDF-SHA512": "testdata/wycheproof_hkdf_sha512.json",
	} {
		var f struct {
			TestGroups []struct {
				Tests []struct {
					TcID                 int `json:"tcId"`
					Ikm, Salt, Info, Okm vectors.Hex
					Size                 int
					Result               string
				}
			}
		}
		vectors.Load(t, path, &f)
		n := 0
		for _, g := range f.TestGroups {
			for _, tc := range g.Tests {
				if len(tc.Ikm) < MinIKM || tc.Size < MinLength || tc.Size > MaxLength || tc.Result != "valid" {
					continue
				}
				if got, err := Derive(alg, tc.Ikm, tc.Salt, tc.Info, tc.Size); err != nil || !bytes.Equal(got, tc.Okm) {
					t.Errorf("%s tc %d: %v", alg, tc.TcID, err)
				}
				n++
			}
		}
		if n < 20 {
			t.Fatalf("%s: only %d vectors", alg, n)
		}
	}
}

func TestBounds(t *testing.T) {
	ikm := make([]byte, 32)
	for _, alg := range Algorithms() {
		if _, err := Derive(alg, ikm, nil, []byte("l"), 32); err != nil {
			t.Fatal(alg, err)
		}
		if _, err := Derive(alg, ikm, nil, nil, 8); !errors.Is(err, errors.ErrInputInvalid) {
			t.Fatal(alg, "length 8 accepted")
		}
		if _, err := Derive(alg, ikm[:8], nil, nil, 32); !errors.Is(err, errors.ErrKeyTooShort) {
			t.Fatal(alg, "8-byte ikm accepted")
		}
	}
	for _, alg := range []string{"SP800-108-CTR", "ANSI-X9.63"} {
		if _, err := Derive(alg, ikm, nil, nil, 32); err == nil {
			t.Fatal(alg, "still accepted")
		}
	}
}
