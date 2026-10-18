package gmac

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// C2SP Wycheproof aes_gmac_test.json, 256-bit key, 96-bit nonce groups.
func TestWycheproof(t *testing.T) {
	var f struct {
		TestGroups []struct {
			IvSize, KeySize, TagSize int
			Tests                    []struct {
				TcID              int `json:"tcId"`
				Key, Iv, Msg, Tag vectors.Hex
				Result            string
			}
		}
	}
	vectors.Load(t, "testdata/aes_gmac_test.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		if g.KeySize != 256 || g.IvSize != 96 || g.TagSize != 128 {
			continue
		}
		for _, tc := range g.Tests {
			ok := Verify(tc.Key, tc.Msg, append(append([]byte{}, tc.Iv...), tc.Tag...)) == nil
			if ok != (tc.Result != "invalid") {
				t.Errorf("tc %d: ok=%v result=%s", tc.TcID, ok, tc.Result)
			}
			n++
		}
	}
	if n < 10 {
		t.Fatalf("only %d vectors", n)
	}
}

// GCM specification test case 13 (AES-256, zero key and IV, empty input). UT-MAC-006.
func TestGCMSpec13(t *testing.T) {
	if err := Verify(make([]byte, KeySize), nil, vectors.MustHex("000000000000000000000000"+"530f8afbc74536b9a963b4f1c4cb738b")); err != nil {
		t.Fatal("published tag rejected")
	}
}

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeySize)
	tag, err := Sum(key, []byte("data"))
	if err != nil || len(tag) != TagSize || Verify(key, []byte("data"), tag) != nil {
		t.Fatal("round trip", err)
	}
	if !errors.Is(Verify(key, []byte("dato"), tag), errors.ErrVerificationFailed) {
		t.Fatal("tamper")
	}
	if !errors.Is(Verify(key, []byte("data"), tag[:20]), errors.ErrVerificationFailed) {
		t.Fatal("short tag")
	}
}
