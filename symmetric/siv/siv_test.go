package siv

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// C2SP Wycheproof aes_siv_cmac_test.json, 512-bit-key groups (RFC 5297 AES-256-SIV).
// RFC 5297 appendix A only has 256-bit-key examples, so Wycheproof is the reference here.
func TestWycheproof(t *testing.T) {
	var f struct {
		TestGroups []struct {
			Tests []struct {
				TcID              int `json:"tcId"`
				Key, Aad, Msg, Ct vectors.Hex
				Result            string
			}
		}
	}
	vectors.Load(t, "testdata/wycheproof_aes_siv_cmac.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if len(tc.Key) != KeySize {
				if _, err := Decrypt(tc.Key, tc.Ct, tc.Aad); !errors.Is(err, errors.ErrKeySizeInvalid) {
					t.Errorf("tc %d: %d-byte key accepted", tc.TcID, len(tc.Key))
				}
				continue
			}
			pt, err := Decrypt(tc.Key, tc.Ct, tc.Aad)
			valid := err == nil && bytes.Equal(pt, tc.Msg)
			if valid != (tc.Result == "valid") {
				t.Errorf("tc %d: open ok=%v result=%s", tc.TcID, valid, tc.Result)
			}
			if tc.Result == "valid" {
				if ct, _ := Encrypt(tc.Key, tc.Msg, tc.Aad); !bytes.Equal(ct, tc.Ct) {
					t.Errorf("tc %d: seal mismatch", tc.TcID)
				}
			}
			n++
		}
	}
	if n < 100 {
		t.Fatalf("only %d vectors ran", n)
	}
}

// UT-SYM-011, UT-SYM-012.
func TestDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	a, _ := Encrypt(key, []byte("3171234567890001"), []byte("nik"))
	b, _ := Encrypt(key, []byte("3171234567890001"), []byte("nik"))
	c, _ := Encrypt(key, []byte("3171234567890002"), []byte("nik"))
	if !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("determinism broken")
	}
	if _, err := Decrypt(key, a, []byte("other")); !errors.Is(err, errors.ErrDecryptionFailed) {
		t.Fatal("wrong context opened")
	}
	if _, err := Encrypt(key[:32], nil, nil); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("32-byte key accepted for AES-256-SIV")
	}
	if _, err := Decrypt(key, a[:15], []byte("nik")); !errors.Is(err, errors.ErrCiphertextEmpty) {
		t.Fatal("short ciphertext not rejected")
	}
}

func FuzzOpen(f *testing.F) {
	f.Add(make([]byte, 16), []byte{})
	key := make([]byte, KeySize)
	f.Fuzz(func(t *testing.T, ct, ctx []byte) {
		if _, err := Decrypt(key, ct, ctx); err == nil && len(ct) >= TagSize {
			// Only a genuine encryption may open; re-encrypting must reproduce ct.
			pt, _ := Decrypt(key, ct, ctx)
			again, _ := Encrypt(key, pt, ctx)
			if !bytes.Equal(again, ct) {
				t.Fatal("opened a forged ciphertext")
			}
		}
	})
}
