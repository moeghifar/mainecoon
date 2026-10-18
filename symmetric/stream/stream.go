// Package stream is streaming authenticated encryption for files and large payloads:
// AES-256-GCM-HKDF segmented AEAD from tink-go (streamingaead/subtle). Each file gets a
// fresh random salt; HKDF-SHA256 (RFC 5869) derives a per-file AES-256 key, and every
// 1 MiB segment is sealed with AES-256-GCM (SP 800-38D) under a nonce built from a random
// prefix, the segment counter and a last-segment flag. Truncation, reordering and
// appending are detected.
//
// The construction (Tink "AES-GCM-HKDF Streaming AEAD") is built from approved parts but is
// not itself a NIST mode, so it is unavailable in fips_only.
package stream

import (
	"io"

	tink "github.com/tink-crypto/tink-go/v2/streamingaead/subtle"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KeySize     = 32
	SegmentSize = 1 << 20
)

func cipher(key []byte) (*tink.AESGCMHKDF, error) {
	if len(key) != KeySize {
		return nil, errors.ErrKeySizeInvalid.With("AES-256-GCM-HKDF-1MB needs a 32-byte key")
	}
	return tink.NewAESGCMHKDF(key, "SHA256", KeySize, SegmentSize, 0)
}

// Encrypt returns a writer that encrypts into w. Close it to write the final segment;
// output without the final segment does not decrypt.
func Encrypt(key []byte, w io.Writer, aad []byte) (io.WriteCloser, error) {
	c, err := cipher(key)
	if err != nil {
		return nil, err
	}
	return c.NewEncryptingWriter(w, aad)
}

// Decrypt returns a reader that decrypts r. A read error means the stream was altered,
// truncated or sealed with another key or aad; discard everything read so far.
func Decrypt(key []byte, r io.Reader, aad []byte) (io.Reader, error) {
	c, err := cipher(key)
	if err != nil {
		return nil, err
	}
	d, err := c.NewDecryptingReader(r, aad)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	return failClosed{d}, nil
}

type failClosed struct{ r io.Reader }

func (f failClosed) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err != nil && err != io.EOF {
		return n, errors.ErrDecryptionFailed
	}
	return n, err
}
