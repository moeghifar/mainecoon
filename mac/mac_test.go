package mac

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// UT-MAC-001, 002: RFC 4231 test case 6 (131-byte key, so it passes the key-size floor).
func TestHMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0xaa}, 131)
	msg := []byte("Test Using Larger Than Block-Size Key - Hash Key First")
	for alg, want := range map[string]string{
		"HMAC-SHA256": "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		"HMAC-SHA384": "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
		"HMAC-SHA512": "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
	} {
		got, err := Sum(alg, key, msg)
		if err != nil || hex.EncodeToString(got) != want {
			t.Errorf("%s: %x %v", alg, got, err)
		}
	}
}

// UT-MAC-003, 007, 008 and the key floor.
func TestVerify(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 64)
	for _, alg := range Algorithms() {
		tag, err := Sum(alg, key, []byte("m"))
		if err != nil {
			t.Fatal(alg, err)
		}
		if Verify(alg, key, []byte("m"), tag) != nil {
			t.Fatal(alg, "valid tag rejected")
		}
		wrong := bytes.Repeat([]byte{2}, len(key))
		if !errors.Is(Verify(alg, wrong, []byte("m"), tag), errors.ErrVerificationFailed) {
			t.Fatal(alg, "wrong key verified or errored")
		}
		if !errors.Is(Verify(alg, key, []byte("m"), tag[:len(tag)-1]), errors.ErrVerificationFailed) {
			t.Fatal(alg, "truncated tag verified")
		}
	}
	if _, err := Sum("HMAC-SHA256", key[:16], nil); !errors.Is(err, errors.ErrKeyTooShort) {
		t.Fatal("16-byte HMAC-SHA256 key accepted")
	}
	for _, alg := range []string{"HMAC-SHA1", "HMAC-MD5"} {
		if _, err := Sum(alg, key, nil); !errors.Is(err, errors.ErrAlgorithmDisabled) {
			t.Fatal(alg, "not disabled")
		}
	}
}

// C2SP Wycheproof hmac_sha3_256_test.json, full-length tags with keys at or above the floor.
func TestWycheproofHMACSHA3(t *testing.T) {
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
	vectors.Load(t, "testdata/wycheproof_hmac_sha3_256.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		if g.KeySize < 256 || g.TagSize != 256 {
			continue
		}
		for _, tc := range g.Tests {
			if ok := Verify("HMAC-SHA3-256", tc.Key, tc.Msg, tc.Tag) == nil; ok != (tc.Result == "valid") {
				t.Errorf("tc %d: ok=%v result=%s", tc.TcID, ok, tc.Result)
			}
			n++
		}
	}
	if n < 20 {
		t.Fatalf("only %d vectors", n)
	}
}
