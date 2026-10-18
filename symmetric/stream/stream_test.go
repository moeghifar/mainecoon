package stream

import (
	"bytes"
	"io"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

var key = vectors.MustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

// Known ciphertext produced by tink-go v2.9.0; decrypting it pins the wire format
// (Tink AES-GCM-HKDF streaming: 0x28 header length || 32-byte salt || 7-byte nonce
// prefix || segments). No NIST or RFC vectors exist for this construction.
const known = "28f632d85c98d2d96e6c91f180235ff32a0be5eb00e272036a087b9b7ffb7ca798037f643f1c34b65ec69c6c9e896a50c1dbb6f8706aa231f73616a7acc0a3f1ce6800dcab638ed83c552c77d05a0f"

func seal(t *testing.T, pt, aad []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := Encrypt(key, &b, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pt); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func open(k, ct, aad []byte) ([]byte, error) {
	r, err := Decrypt(k, bytes.NewReader(ct), aad)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestKnownCiphertext(t *testing.T) {
	pt, err := open(key, vectors.MustHex(known), []byte("mainecoon-kat"))
	if err != nil || string(pt) != "mainecoon streaming KAT" {
		t.Fatalf("%q %v", pt, err)
	}
}

// Sizes around the 1 MiB segment boundary (first segment holds less: header + tag).
func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, SegmentSize - 41 - 16, SegmentSize - 40 - 16, SegmentSize, 3*SegmentSize + 7} {
		pt := bytes.Repeat([]byte{byte(n)}, n) //nolint:gosec // test filler, wrap is fine
		got, err := open(key, seal(t, pt, []byte("file.pdf")), []byte("file.pdf"))
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
}

func TestTamperDetected(t *testing.T) {
	pt := bytes.Repeat([]byte("x"), 2*SegmentSize+100)
	ct := seal(t, pt, []byte("a"))
	flip := append([]byte{}, ct...)
	flip[len(flip)/2] ^= 1
	for name, c := range map[string]struct {
		k, ct, aad []byte
	}{
		"wrong aad":    {key, ct, []byte("b")},
		"wrong key":    {bytes.Repeat([]byte{9}, KeySize), ct, []byte("a")},
		"bit flip":     {key, flip, []byte("a")},
		"truncated":    {key, ct[:SegmentSize+40], []byte("a")},
		"last seg cut": {key, ct[:len(ct)-1], []byte("a")},
		"appended":     {key, append(append([]byte{}, ct...), 0), []byte("a")},
		"header only":  {key, ct[:40], []byte("a")},
	} {
		if _, err := open(c.k, c.ct, c.aad); !errors.Is(err, errors.ErrDecryptionFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFreshSaltPerFile(t *testing.T) {
	if bytes.Equal(seal(t, []byte("same"), nil), seal(t, []byte("same"), nil)) {
		t.Fatal("two encryptions of the same file are equal")
	}
}

func TestRejects(t *testing.T) {
	if _, err := Encrypt(key[:16], io.Discard, nil); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("16-byte key accepted")
	}
}
