package aead

import (
	"bytes"
	"testing"
	"time"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

type wycheproof struct {
	TestGroups []struct {
		IvSize, KeySize, TagSize int
		Tests                    []struct {
			TcID                       int `json:"tcId"`
			Key, Iv, Aad, Msg, Ct, Tag vectors.Hex
			Result                     string
		}
	}
}

// C2SP Wycheproof aes_gcm_test.json and chacha20_poly1305_test.json, 256-bit key, 96-bit
// nonce, 128-bit tag groups: every valid vector decrypts, every invalid one fails.
func TestWycheproof(t *testing.T) {
	for alg, path := range map[Alg]string{
		AES256GCM:        "testdata/aes_gcm_test.json",
		ChaCha20Poly1305: "testdata/chacha20_poly1305_test.json",
	} {
		var f wycheproof
		vectors.Load(t, path, &f)
		n := 0
		for _, g := range f.TestGroups {
			if g.KeySize != 256 || g.IvSize != 96 || g.TagSize != 128 {
				continue
			}
			for _, tc := range g.Tests {
				ct := append(append(append([]byte{}, tc.Iv...), tc.Ct...), tc.Tag...)
				pt, err := Decrypt(alg, tc.Key, ct, tc.Aad)
				ok := err == nil && bytes.Equal(pt, tc.Msg)
				if ok != (tc.Result != "invalid") {
					t.Errorf("%s tc %d: ok=%v result=%s", alg, tc.TcID, ok, tc.Result)
				}
				n++
			}
		}
		if n < 50 {
			t.Fatalf("%s: only %d vectors", alg, n)
		}
	}
}

// GCM specification (McGrew & Viega) test case 16 and RFC 8439 §2.8.2, in nonce‖ct‖tag form.
func TestPublishedVectors(t *testing.T) {
	for _, v := range []struct {
		alg                      Alg
		key, nonce, aad, ct, tag string
		pt                       string
	}{
		{AES256GCM, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"},
		{ChaCha20Poly1305, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "070000004041424344454647", "50515253c0c1c2c3c4c5c6c7",
			"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", "1ae10b594f09e26a7e902ecbd0600691",
			"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"},
	} {
		ct := vectors.MustHex(v.nonce + v.ct + v.tag)
		pt, err := Decrypt(v.alg, vectors.MustHex(v.key), ct, vectors.MustHex(v.aad))
		if err != nil || !bytes.Equal(pt, vectors.MustHex(v.pt)) {
			t.Errorf("%s: %v", v.alg, err)
		}
	}
}

// UT-SYM-001..006, 008, 013, 014.
func TestRoundTripAndRejections(t *testing.T) {
	key := bytes.Repeat([]byte{3}, KeySize)
	for _, alg := range []Alg{AES256GCM, ChaCha20Poly1305} {
		c1, err := Encrypt(alg, key, []byte("hello"), []byte("ctx"))
		if err != nil || len(c1) != 5+Overhead {
			t.Fatal(alg, err, len(c1))
		}
		c2, _ := Encrypt(alg, key, []byte("hello"), []byte("ctx"))
		if bytes.Equal(c1[:NonceSize], c2[:NonceSize]) {
			t.Fatal(alg, "nonce reused")
		}
		if pt, err := Decrypt(alg, key, c1, []byte("ctx")); err != nil || string(pt) != "hello" {
			t.Fatal(alg, "round trip")
		}
		flip := bytes.Clone(c1)
		flip[NonceSize] ^= 1
		for name, c := range map[string]struct{ key, ct, aad []byte }{
			"wrong key": {bytes.Repeat([]byte{4}, KeySize), c1, []byte("ctx")},
			"tamper":    {key, flip, []byte("ctx")},
			"aad":       {key, c1, []byte("ctY")},
			"truncated": {key, c1[:len(c1)-1], []byte("ctx")},
		} {
			if _, err := Decrypt(alg, c.key, c.ct, c.aad); !errors.Is(err, errors.ErrDecryptionFailed) {
				t.Fatal(alg, name, err)
			}
		}
		if c, err := Encrypt(alg, key, nil, nil); err != nil || len(c) != Overhead {
			t.Fatal(alg, "empty plaintext")
		} else if pt, err := Decrypt(alg, key, c, nil); err != nil || len(pt) != 0 {
			t.Fatal(alg, "empty round trip")
		}
		if _, err := Encrypt(alg, key[:16], nil, nil); !errors.Is(err, errors.ErrKeySizeInvalid) {
			t.Fatal(alg, "16-byte key accepted")
		}
		if _, err := Decrypt(alg, key, c1[:Overhead-1], nil); !errors.Is(err, errors.ErrCiphertextEmpty) {
			t.Fatal(alg, "short ciphertext")
		}
	}
	for _, alg := range []Alg{"AES-256-CBC", "AES-256-ECB", "AES-128-GCM"} {
		if _, err := Encrypt(alg, key, nil, nil); !errors.Is(err, errors.ErrAlgorithmDisabled) {
			t.Fatal(alg, "not disabled")
		}
	}
}

// UT-SYM-007: 10 MB in under a second.
func TestThroughput(t *testing.T) {
	start := time.Now()
	if _, err := Encrypt(AES256GCM, make([]byte, KeySize), make([]byte, 10<<20), nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("10MB took %v", d)
	}
}
