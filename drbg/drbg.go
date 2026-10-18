// Package drbg returns random bytes from Go's crypto/rand, which is an SP 800-90A
// CTR_DRBG (AES-256) inside the Go FIPS 140-3 module, seeded from the OS. The module runs
// its own SP 800-90B health tests and CAST; crypto/rand never returns a short read (it
// aborts the process on an RNG failure), so nothing is added here but the F1 bounds.
package drbg

import (
	"crypto/rand"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	MinBytes = 16
	MaxBytes = 8192
)

// Bytes returns n random bytes, MinBytes <= n <= MaxBytes (cryptop F1).
func Bytes(n int) ([]byte, error) {
	if n < MinBytes || n > MaxBytes {
		return nil, errors.ErrInputInvalid.With("random length must be 16..8192")
	}
	b := make([]byte, n)
	rand.Read(b)
	return b, nil
}

// Read fills b with random bytes, any length; used for keys, nonces and salts.
func Read(b []byte) error {
	rand.Read(b)
	return nil
}
