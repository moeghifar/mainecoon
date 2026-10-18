package cmac

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// NIST SP 800-38B Appendix D.3 (AES-256), examples 1 and 2. UT-MAC-005.
func TestSP80038B(t *testing.T) {
	key := vectors.MustHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	for msg, want := range map[string]string{
		"":                                 "028962f61b7bf89efc6b551f4667d983",
		"6bc1bee22e409f96e93d7e117393172a": "28a7023f452e8f82bd4bf28d8c37c35c",
	} {
		got, _ := Sum(key, vectors.MustHex(msg))
		if hex.EncodeToString(got) != want {
			t.Errorf("CMAC(%s) = %x", msg, got)
		}
	}
}

// C2SP Wycheproof aes_cmac_test.json, 256-bit-key groups with full 16-byte tags.
func TestWycheproof(t *testing.T) {
	var f struct {
		TestGroups []struct {
			KeySize, TagSize int
			Tests            []struct {
				TcID          int `json:"tcId"`
				Key, Msg, Tag vectors.Hex
				Result        string
			}
		}
	}
	vectors.Load(t, "testdata/wycheproof_aes_cmac.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		if g.KeySize != 256 || g.TagSize != 128 {
			continue
		}
		for _, tc := range g.Tests {
			if ok := Verify(tc.Key, tc.Msg, tc.Tag) == nil; ok != (tc.Result == "valid") {
				t.Errorf("tc %d: ok=%v result=%s", tc.TcID, ok, tc.Result)
			}
			n++
		}
	}
	if n < 30 {
		t.Fatalf("only %d vectors ran", n)
	}
}

// UT-MAC-003, 007, 008.
func TestVerify(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeySize)
	tag, _ := Sum(key, []byte("m"))
	if Verify(key, []byte("m"), tag) != nil {
		t.Fatal("valid tag rejected")
	}
	for name, err := range map[string]error{
		"wrong key": Verify(bytes.Repeat([]byte{2}, KeySize), []byte("m"), tag),
		"truncated": Verify(key, []byte("m"), tag[:15]),
		"message":   Verify(key, []byte("n"), tag),
	} {
		if !errors.Is(err, errors.ErrVerificationFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Sum(key[:16], nil); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("16-byte key accepted")
	}
}
