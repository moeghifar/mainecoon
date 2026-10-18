// Package cmac is AES-256-CMAC (SP 800-38B) from tink-go. Verification is constant time.
package cmac

import (
	tink "github.com/tink-crypto/tink-go/v2/mac/subtle"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KeySize = 32
	TagSize = 16
)

// Sum returns the 16-byte tag of data.
func Sum(key, data []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.ErrKeySizeInvalid.With("AES-256-CMAC needs a 32-byte key")
	}
	c, _ := tink.NewAESCMAC(key, TagSize)
	return c.ComputeMAC(data)
}

// Verify returns nil for a valid tag and ErrVerificationFailed otherwise.
func Verify(key, data, tag []byte) error {
	if len(key) != KeySize {
		return errors.ErrKeySizeInvalid.With("AES-256-CMAC needs a 32-byte key")
	}
	c, _ := tink.NewAESCMAC(key, TagSize)
	if c.VerifyMAC(tag, data) != nil {
		return errors.ErrVerificationFailed
	}
	return nil
}
