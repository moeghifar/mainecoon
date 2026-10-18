// Package token is mainecoon's text ciphertext encoding, modelled on Vault transit
// ("vault:v1:<base64>"):
//
//	mc:<alg>:v<version>:<base64(ciphertext)>
//	mc:aes-gcm-256:v3:2Vz0...   AES-256-GCM, key version 3, nonce ‖ ct ‖ tag
//
// alg is a code (aes-gcm-256, chacha20-poly1305, aes-siv-256), so a token says how to decrypt it and
// algorithms can rotate. version is the key version (≥ 1), so keys can rotate: Decrypt asks
// the caller's Keyring for that version. As in Vault, the key *name* is not in the token;
// the caller (xandi KMS) knows which key it is using.
//
// The header "mc:<alg>:v<version>:" is bound into the AEAD associated data, so changing the
// algorithm or version in a token makes it fail to decrypt.
package token

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/symmetric/aead"
	"github.com/moeghifar/mainecoon/symmetric/siv"
)

const (
	prefix = "mc"
	b64    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

type codec struct {
	enc func(key, pt, aad []byte) ([]byte, error)
	dec func(key, ct, aad []byte) ([]byte, error)
}

func aeadCodec(a aead.Alg) codec {
	return codec{
		func(k, p, d []byte) ([]byte, error) { return aead.Encrypt(a, k, p, d) },
		func(k, c, d []byte) ([]byte, error) { return aead.Decrypt(a, k, c, d) },
	}
}

// Codes maps a token code to its registry algorithm ID.
var Codes = map[string]string{
	"aes-gcm-256":       string(aead.AES256GCM),
	"chacha20-poly1305": string(aead.ChaCha20Poly1305),
	"aes-siv-256":       "AES-256-SIV",
}

var codecs = map[string]codec{
	"aes-gcm-256":       aeadCodec(aead.AES256GCM),
	"chacha20-poly1305": aeadCodec(aead.ChaCha20Poly1305),
	"aes-siv-256":       {siv.Encrypt, siv.Decrypt},
}

// Keyring returns the key for a key version, or an error (e.g. ErrKeyNotFound).
type Keyring func(version uint32) ([]byte, error)

// Encrypt seals plaintext under key (version `version`) and returns a token.
// code is a short algorithm code from Codes.
func Encrypt(code string, key []byte, version uint32, plaintext, aad []byte) (string, error) {
	c, ok := codecs[code]
	if !ok {
		return "", errors.ErrAlgorithmDisabled.With("unknown token algorithm " + code)
	}
	if version == 0 {
		return "", errors.ErrInputInvalid.With("key version starts at 1")
	}
	h := header(code, version)
	ct, err := c.enc(key, plaintext, bind(h, aad))
	if err != nil {
		return "", err
	}
	return h + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt opens a token, fetching the key for its version from keys.
func Decrypt(keys Keyring, tok string, aad []byte) ([]byte, error) {
	code, version, ct, err := Parse(tok)
	if err != nil {
		return nil, err
	}
	key, err := keys(version)
	if err != nil {
		return nil, err
	}
	return codecs[code].dec(key, ct, bind(header(code, version), aad))
}

// Parse splits a token into its algorithm code, key version and raw ciphertext.
func Parse(tok string) (code string, version uint32, ciphertext []byte, err error) {
	bad := errors.ErrEnvelopeInvalid.With("token is not mc:<alg>:v<n>:<base64>")
	rest, ok := strings.CutPrefix(tok, prefix+":")
	if !ok {
		return "", 0, nil, bad
	}
	code, rest, ok1 := strings.Cut(rest, ":")
	ver, payload, ok2 := strings.Cut(rest, ":")
	if !ok1 || !ok2 || len(ver) < 2 || ver[0] != 'v' || payload == "" {
		return "", 0, nil, bad
	}
	if _, ok := codecs[code]; !ok {
		return "", 0, nil, errors.ErrAlgorithmDisabled.With("unknown token algorithm " + code)
	}
	v, err := strconv.ParseUint(ver[1:], 10, 32)
	if err != nil || v == 0 || ver[1] == '0' {
		return "", 0, nil, errors.ErrEnvelopeInvalid.With("bad key version")
	}
	// Go's decoder skips \r and \n even in Strict mode; a token must be exactly one form.
	if strings.ContainsFunc(payload, func(r rune) bool { return !strings.ContainsRune(b64, r) }) {
		return "", 0, nil, errors.ErrEnvelopeInvalid.With("bad base64")
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return "", 0, nil, errors.ErrEnvelopeInvalid.With("bad base64")
	}
	return code, uint32(v), ct, nil
}

func header(code string, version uint32) string {
	return prefix + ":" + code + ":v" + strconv.FormatUint(uint64(version), 10) + ":"
}

// bind prefixes the header to the caller's aad. The header ends in ':' and is parsed with a
// fixed grammar, so header ‖ aad is unambiguous.
func bind(h string, aad []byte) []byte { return append([]byte(h), aad...) }
