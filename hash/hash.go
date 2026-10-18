// Package hash computes digests (cryptop F2) and extendable-output functions (F3).
package hash

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	stdhash "hash"
	"io"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

var hashes = map[string]func() stdhash.Hash{
	"SHA-256":  sha256.New,
	"SHA-384":  sha512.New384,
	"SHA-512":  sha512.New,
	"SHA3-256": func() stdhash.Hash { return sha3.New256() },
	"SHA3-384": func() stdhash.Hash { return sha3.New384() },
	"SHA3-512": func() stdhash.Hash { return sha3.New512() },
}

var xofs = map[string]func() *sha3.SHAKE{
	"SHAKE128": sha3.NewSHAKE128,
	"SHAKE256": sha3.NewSHAKE256,
}

const (
	MinXOFBytes = 16
	MaxXOFBytes = 512
)

func Algorithms() []string    { return reg.IDs(hashes) }
func XOFAlgorithms() []string { return reg.IDs(xofs) }

// New returns a streaming hash.
func New(alg string) (stdhash.Hash, error) {
	f, err := reg.Lookup(hashes, alg)
	if err != nil {
		return nil, err
	}
	return f(), nil
}

// Func returns the constructor, for HMAC, HKDF and PBKDF2.
func Func(alg string) (func() stdhash.Hash, error) { return reg.Lookup(hashes, alg) }

// Sum returns the digest of data.
func Sum(alg string, data []byte) ([]byte, error) {
	h, err := New(alg)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// SumReader streams r into the digest.
func SumReader(alg string, r io.Reader) ([]byte, error) {
	h, err := New(alg)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(h, r); err != nil {
		return nil, errors.ErrInputInvalid.With(err.Error())
	}
	return h.Sum(nil), nil
}

// XOF returns n bytes of SHAKE output, MinXOFBytes <= n <= MaxXOFBytes.
func XOF(alg string, data []byte, n int) ([]byte, error) {
	f, err := reg.Lookup(xofs, alg)
	if err != nil {
		return nil, err
	}
	if n < MinXOFBytes || n > MaxXOFBytes {
		return nil, errors.ErrInputInvalid.With("xof output must be 16..512 bytes")
	}
	x := f()
	x.Write(data)
	out := make([]byte, n)
	x.Read(out)
	return out, nil
}
