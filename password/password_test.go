package password

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"golang.org/x/crypto/scrypt"
)

var salt = bytes.Repeat([]byte{0x5a}, 16)

// The algorithms behind the floors, checked against RFC 7914 section 11 vectors.
func TestRFC7914(t *testing.T) {
	k, _ := pbkdf2.Key(sha256.New, "passwd", []byte("salt"), 1, 64)
	if hex.EncodeToString(k) != "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783" {
		t.Fatal("PBKDF2-HMAC-SHA256")
	}
	s, _ := scrypt.Key(nil, nil, 16, 1, 1, 64)
	if hex.EncodeToString(s) != "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906" {
		t.Fatal("scrypt")
	}
}

// UT-KDF-004 (600k), 005.
func TestPBKDF2(t *testing.T) {
	if testing.Short() {
		t.Skip("600k iterations")
	}
	a, err := DeriveKey("PBKDF2-SHA256", "correct horse", salt, Params{}, 32)
	if err != nil || len(a) != 32 {
		t.Fatal(err)
	}
	want, _ := pbkdf2.Key(sha256.New, "correct horse", salt, PBKDF2SHA256MinIter, 32)
	if !bytes.Equal(a, want) {
		t.Fatal("default iterations are not the floor")
	}
	if _, err := DeriveKey("PBKDF2-SHA256", "pw", salt, Params{Iterations: 599_999}, 32); !errors.Is(err, errors.ErrIterationsBelowFloor) {
		t.Fatal("below floor accepted")
	}
	if _, err := DeriveKey("PBKDF2-SHA384", "pw", salt, Params{Iterations: 100_000}, 32); !errors.Is(err, errors.ErrIterationsBelowFloor) {
		t.Fatal("SHA384 below floor accepted")
	}
}

// UT-KDF-006, 007.
func TestArgon2idKDF(t *testing.T) {
	a, _ := DeriveKey("Argon2id", "pw", salt, Params{}, 32)
	b, _ := DeriveKey("Argon2id", "pw", salt, Params{}, 32)
	c, _ := DeriveKey("Argon2id", "pw", bytes.Repeat([]byte{1}, 16), Params{}, 32)
	if !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("argon2id determinism or salt binding")
	}
	if _, err := DeriveKey("Argon2id", "pw", salt, Params{MemoryKiB: 1024}, 32); !errors.Is(err, errors.ErrParameterBelowFloor) {
		t.Fatal("weak argon2 accepted")
	}
	if _, err := DeriveKey("Argon2id", "pw", salt, Params{MemoryKiB: 1 << 30}, 32); !errors.Is(err, errors.ErrParameterBelowFloor) {
		t.Fatal("huge argon2 memory accepted")
	}
	if _, err := DeriveKey("Argon2id", "pw", salt[:8], Params{}, 32); !errors.Is(err, errors.ErrInputInvalid) {
		t.Fatal("short salt accepted")
	}
	if _, err := DeriveKey("scrypt", "pw", salt, Params{N: 1024}, 32); !errors.Is(err, errors.ErrParameterBelowFloor) {
		t.Fatal("weak scrypt accepted")
	}
	if k, err := DeriveKey("scrypt", "pw", salt, Params{}, 32); err != nil || len(k) != 32 {
		t.Fatal(err)
	}
}

func TestHashVerify(t *testing.T) {
	for _, alg := range []string{"Argon2id", "bcrypt"} {
		h, err := Hash(alg, "s3cret", Params{})
		if err != nil {
			t.Fatal(alg, err)
		}
		if ok, err := Verify("s3cret", h); !ok || err != nil {
			t.Fatal(alg, "verify", err)
		}
		if ok, _ := Verify("s3creT", h); ok {
			t.Fatal(alg, "wrong password verified")
		}
	}
	if _, err := Hash("bcrypt", strings.Repeat("a", 73), Params{}); !errors.Is(err, errors.ErrInputTooLarge) {
		t.Fatal("bcrypt 73 bytes accepted")
	}
	if _, err := Hash("bcrypt", "pw", Params{Cost: 10}); !errors.Is(err, errors.ErrParameterBelowFloor) {
		t.Fatal("bcrypt cost 10 accepted")
	}
	// A hash string demanding 4 GiB must be refused, not computed.
	evil := "$argon2id$v=19$m=4194304,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
	if _, err := Verify("x", evil); !errors.Is(err, errors.ErrParameterBelowFloor) {
		t.Fatal("unbounded argon2 hash accepted:", err)
	}
	if _, err := Verify("x", "$1$md5crypt"); !errors.Is(err, errors.ErrAlgorithmDisabled) {
		t.Fatal("md5crypt accepted")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")
	f.Add("$2b$12$abcdefghijklmnopqrstuu")
	f.Fuzz(func(t *testing.T, h string) {
		if strings.HasPrefix(h, "$argon2id$") {
			// Bounds are checked before any work: oversized params must error out fast.
			var m, tc uint32
			var p uint8
			parts := strings.Split(h, "$")
			if len(parts) == 6 {
				if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &tc, &p); err == nil && (m > ArgonMaxMemKiB || tc > ArgonMaxTime) {
					if _, err := Verify("x", h); err == nil {
						t.Fatal("out-of-bounds params accepted")
					}
					return
				}
			}
			if len(h) > 200 {
				return
			}
		}
		_, _ = Verify("x", h)
	})
}

func TestVerifyRejectsShortSalt(t *testing.T) {
	// 8-byte salt, otherwise valid parameters.
	h := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
	if _, err := Verify("x", h); !errors.Is(err, errors.ErrInputInvalid) {
		t.Fatal("8-byte salt accepted:", err)
	}
}
