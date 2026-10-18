// Package kwp is AES-256 key wrap with padding (SP 800-38F KWP, RFC 5649) from tink-go
// (cryptop F17). Unwrapping verifies integrity itself; no extra MAC is needed.
// AES-256-KW (unpadded) is not offered: no maintained Go library, and KWP covers it.
// tink limits: Wrap takes 16..8192 bytes; Unwrap rejects the 16-byte single-block form.
package kwp

import (
	"crypto/subtle"

	tink "github.com/tink-crypto/tink-go/v2/kwp/subtle"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KEKSize = 32
	MinSize = tink.MinWrapSize // 16 bytes
	MaxSize = tink.MaxWrapSize // 8192 bytes
)

func kek(k []byte) (*tink.KWP, error) {
	if len(k) != KEKSize {
		return nil, errors.ErrKeySizeInvalid.With("AES-256-KWP needs a 32-byte wrapping key")
	}
	return tink.NewKWP(k)
}

// Wrap wraps 16..8192 bytes of key material under kek.
func Wrap(kekBytes, key []byte) ([]byte, error) {
	w, err := kek(kekBytes)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(kekBytes, key) == 1 {
		return nil, errors.ErrInputInvalid.With("a key cannot wrap itself")
	}
	if len(key) < MinSize || len(key) > MaxSize {
		return nil, errors.ErrInputInvalid.With("KWP input must be 16..8192 bytes")
	}
	return w.Wrap(key)
}

// Unwrap returns the key material, or ErrDecryptionFailed on any integrity failure.
func Unwrap(kekBytes, wrapped []byte) ([]byte, error) {
	w, err := kek(kekBytes)
	if err != nil {
		return nil, err
	}
	pt, err := w.Unwrap(wrapped)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	return pt, nil
}
