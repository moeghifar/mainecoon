package token

import (
	"bytes"
	"strings"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
)

func ring(keys map[uint32][]byte) Keyring {
	return func(v uint32) ([]byte, error) {
		if k, ok := keys[v]; ok {
			return k, nil
		}
		return nil, errors.ErrKeyNotFound
	}
}

func TestRoundTripAllCodes(t *testing.T) {
	k32, k64 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64)
	for code := range Codes {
		key := k32
		if code == "aes-siv-256" {
			key = k64
		}
		tok, err := Encrypt(code, key, 3, []byte("3171234567890001"), []byte("sipd.NIK"))
		if err != nil || !strings.HasPrefix(tok, "mc:"+code+":v3:") {
			t.Fatalf("%s: %q %v", code, tok, err)
		}
		pt, err := Decrypt(ring(map[uint32][]byte{3: key}), tok, []byte("sipd.NIK"))
		if err != nil || string(pt) != "3171234567890001" {
			t.Fatalf("%s: %v", code, err)
		}
	}
}

// Rotation: old tokens keep opening with their version; new ones use the new key.
func TestKeyRotation(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	old, _ := Encrypt("aes-gcm-256", k1, 1, []byte("a"), nil)
	cur, _ := Encrypt("aes-gcm-256", k2, 2, []byte("b"), nil)
	keys := ring(map[uint32][]byte{1: k1, 2: k2})
	if p, err := Decrypt(keys, old, nil); err != nil || string(p) != "a" {
		t.Fatal("v1", err)
	}
	if p, err := Decrypt(keys, cur, nil); err != nil || string(p) != "b" {
		t.Fatal("v2", err)
	}
	if _, err := Decrypt(ring(map[uint32][]byte{2: k2}), old, nil); !errors.Is(err, errors.ErrKeyNotFound) {
		t.Fatal("retired version opened", err)
	}
}

// The header is authenticated: rewriting version or algorithm breaks decryption.
func TestHeaderBound(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 32)
	tok, _ := Encrypt("aes-gcm-256", k, 1, []byte("x"), []byte("ctx"))
	keys := ring(map[uint32][]byte{1: k, 2: k})
	for name, c := range map[string]struct {
		tok string
		aad []byte
	}{
		"version swapped": {strings.Replace(tok, ":v1:", ":v2:", 1), []byte("ctx")},
		"alg swapped":     {strings.Replace(tok, ":aes-gcm-256:", ":chacha20-poly1305:", 1), []byte("ctx")},
		"wrong aad":       {tok, []byte("ctY")},
	} {
		if _, err := Decrypt(keys, c.tok, c.aad); !errors.Is(err, errors.ErrDecryptionFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	keys := ring(nil)
	for _, tok := range []string{
		"", "vault:v1:AAAA", "mc$aes-gcm-256:v1#AAAA", "mc:aes-gcm-256:1:AAAA", "mc:aes-gcm-256:v0:AAAA",
		"mc:aes-gcm-256:v01:AAAA", "mc:aes-gcm-256:v1:!!!", "mc:aes-gcm-256:v4294967296:AAAA",
		"mc:aes-gcm-256:v:AAAA", "mc:v1:AAAA", "aes-gcm-256:v1:AAAA",
		"mc:aes-gcm-256:v1",           // payload missing
		"mc:aes-gcm-256:v1:",          // empty payload
		"mc:aes-gcm-256:v1:\r",        // decoder would skip CR
		"mc:aes-gcm-256:v1:AA\nAA",    // embedded newline
		"mc:aes-gcm-256:v1:AAAA:AAAA", // extra field
	} {
		if _, err := Decrypt(keys, tok, nil); !errors.Is(err, errors.ErrEnvelopeInvalid) {
			t.Errorf("%q: %v", tok, err)
		}
	}
	if _, err := Decrypt(keys, "mc:aes-cbc-128:v1:AAAA", nil); !errors.Is(err, errors.ErrAlgorithmDisabled) {
		t.Error("unknown alg")
	}
	if _, err := Encrypt("aes-gcm-256", make([]byte, 32), 0, nil, nil); !errors.Is(err, errors.ErrInputInvalid) {
		t.Error("version 0 accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("mc:aes-gcm-256:v1:AAAA")
	f.Fuzz(func(t *testing.T, tok string) {
		code, v, ct, err := Parse(tok)
		if err == nil && (v == 0 || Codes[code] == "" || len(ct) == 0) {
			t.Fatalf("accepted %q", tok)
		}
	})
}
