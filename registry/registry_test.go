package registry

import (
	"testing"

	"github.com/moeghifar/mainecoon/errors"
)

func TestLookup(t *testing.T) {
	if i, err := Lookup("AES-256-GCM"); err != nil || !i.FIPS || i.Family != AEAD {
		t.Fatal(i, err)
	}
	for _, id := range []string{"RSA-PSS-1024", "RSA-OAEP-1024"} {
		if _, err := Lookup(id); !errors.Is(err, errors.ErrParameterBelowFloor) {
			t.Error(id, err)
		}
	}
	for _, id := range []string{"MD5", "SHA-1", "3DES", "AES-256-CBC", "RSA-PKCS1-v1.5", "FF3-1", "AES-256-KW", "SP800-108-CTR", "ECDSA-P256+ML-DSA-65"} {
		if _, err := Lookup(id); !errors.Is(err, errors.ErrAlgorithmDisabled) {
			t.Error(id, err)
		}
	}
}

func TestConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range All() {
		if seen[a.ID] || a.Standard == "" || a.Family == "" {
			t.Errorf("bad entry %+v", a)
		}
		seen[a.ID] = true
		if a.Hybrid && !a.PQ {
			t.Errorf("%s hybrid without PQ", a.ID)
		}
	}
}

func TestStrength(t *testing.T) {
	for _, a := range All() {
		password := a.Family == PasswordKDF || a.Family == PasswordHash
		if (a.Strength == 0) != password {
			t.Errorf("%s: strength %d", a.ID, a.Strength)
		}
		if a.Strength > 0 && a.Strength < 112 {
			t.Errorf("%s: below 112 bits", a.ID)
		}
	}
}
