package drbg

import (
	"bytes"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
)

// UT-RNG-001..003.
func TestBytes(t *testing.T) {
	a, err := Bytes(32)
	b, _ := Bytes(32)
	if err != nil || len(a) != 32 || bytes.Equal(a, b) || bytes.Equal(a, make([]byte, 32)) {
		t.Fatal("random output broken")
	}
	for _, n := range []int{0, 15, 8193} {
		if _, err := Bytes(n); !errors.Is(err, errors.ErrInputInvalid) {
			t.Fatal(n, "accepted")
		}
	}
	if b, _ := Bytes(MaxBytes); len(b) != MaxBytes {
		t.Fatal("max length")
	}
}
