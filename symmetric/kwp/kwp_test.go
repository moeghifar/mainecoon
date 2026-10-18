package kwp

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// Wrap is limited to 16..8192 bytes of key material under a 256-bit KEK; unwrap
// accepts every RFC 5649 length. Vectors are checked against that domain.
func inDomain(key, pt []byte) bool {
	return len(key) == KEKSize && len(pt) >= MinSize && len(pt) <= MaxSize
}

// C2SP Wycheproof aes_kwp_test.json.
func TestWycheproofKWP(t *testing.T) {
	var f struct {
		TestGroups []struct {
			Tests []struct {
				TcID         int `json:"tcId"`
				Key, Msg, Ct vectors.Hex
				Result       string
			}
		}
	}
	vectors.Load(t, "testdata/wycheproof_aes_kwp.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if len(tc.Key) != KEKSize || tc.Result == "acceptable" {
				continue
			}
			pt, err := Unwrap(tc.Key, tc.Ct)
			ok := err == nil && bytes.Equal(pt, tc.Msg)
			if ok != (tc.Result == "valid" && len(tc.Ct) != 16) { // single-block form: see TestACVPKWP
				t.Errorf("tc %d: unwrap ok=%v result=%s", tc.TcID, ok, tc.Result)
			}
			if tc.Result == "valid" && inDomain(tc.Key, tc.Msg) {
				if ct, err := Wrap(tc.Key, tc.Msg); err != nil || !bytes.Equal(ct, tc.Ct) {
					t.Errorf("tc %d: wrap mismatch %v", tc.TcID, err)
				}
			}
			n++
		}
	}
	if n < 50 {
		t.Fatalf("only %d vectors", n)
	}
}

// NIST ACVP KeyWrap-KWP (SP 800-38F), AES-256 groups.
func TestACVPKWP(t *testing.T) {
	var f struct {
		TestGroups []struct {
			Direction string
			Tests     []struct {
				TcID        int `json:"tcId"`
				Key, Pt, Ct vectors.Hex
				TestPassed  *bool
			}
		}
	}
	vectors.Load(t, "testdata/acvp_kwp.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if len(tc.Key) != KEKSize {
				continue
			}
			pass := tc.TestPassed == nil || *tc.TestPassed
			if g.Direction == "encrypt" {
				ct, err := Wrap(tc.Key, tc.Pt)
				if inDomain(tc.Key, tc.Pt) != (err == nil) || (err == nil && !bytes.Equal(ct, tc.Ct)) {
					t.Errorf("tc %d wrap: %v", tc.TcID, err)
				}
				n++
				continue
			}
			pt, err := Unwrap(tc.Key, tc.Ct)
			ok := err == nil && bytes.Equal(pt, tc.Pt)
			if len(tc.Ct) == 16 { // single-block form (≤8-byte key material): not supported by tink, must fail closed
				if ok {
					t.Errorf("tc %d: 16-byte ciphertext unwrapped", tc.TcID)
				}
				continue
			}
			if ok != pass {
				t.Errorf("tc %d unwrap: err=%v want pass=%v", tc.TcID, err, pass)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no AES-256 vectors")
	}
}

// UT-KW-001, 002, 004.
func TestPolicy(t *testing.T) {
	kek := bytes.Repeat([]byte{1}, KEKSize)
	dek := bytes.Repeat([]byte{2}, 32)
	w, _ := Wrap(kek, dek)
	if _, err := Unwrap(bytes.Repeat([]byte{3}, KEKSize), w); !errors.Is(err, errors.ErrDecryptionFailed) {
		t.Fatal("wrong KEK unwrapped")
	}
	if _, err := Wrap(kek, kek); !errors.Is(err, errors.ErrInputInvalid) {
		t.Fatal("key wrapped itself")
	}
	for _, n := range []int{16, 20, 33, 100, 8192} {
		w, err := Wrap(kek, bytes.Repeat([]byte{9}, n))
		if err != nil {
			t.Fatal(n, err)
		}
		if p, err := Unwrap(kek, w); err != nil || len(p) != n {
			t.Fatalf("KWP %d bytes", n)
		}
	}
	for _, n := range []int{0, 15, 8193} {
		if _, err := Wrap(kek, make([]byte, n)); !errors.Is(err, errors.ErrInputInvalid) {
			t.Fatalf("KWP accepted %d bytes", n)
		}
	}
	if _, err := Wrap(kek[:16], dek); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("16-byte KEK accepted")
	}
}

func FuzzUnwrap(f *testing.F) {
	f.Add(make([]byte, 24))
	f.Add(make([]byte, 16))
	kek := make([]byte, KEKSize)
	f.Fuzz(func(t *testing.T, in []byte) { Unwrap(kek, in) })
}
