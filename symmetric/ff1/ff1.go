// Package ff1 is format-preserving encryption with FF1 (NIST SP 800-38G Rev 1) from
// github.com/capitalone/fpe, cryptop F9: a 16-digit NIK encrypts to another 16-digit string.
// FF3-1 is not offered: NIST withdrew it in the SP 800-38G Rev 1 second draft (2025).
//
// Radix is limited to 62 (capitalone works on math/big numeral strings). The domain must be
// at least 10^6 (SP 800-38G Rev 1), checked here before calling the library.
package ff1

import (
	"math"
	"strings"
	"unicode/utf8"

	capitalone "github.com/capitalone/fpe/ff1"

	"github.com/moeghifar/mainecoon/errors"
)

const (
	KeySize  = 32
	MaxTweak = 256
	MaxLen   = 4096
	MaxRadix = len(numerals) // 62
	digits   = "0123456789"
	letters  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals = digits + letters // math/big digit order used by capitalone
)

// Alphabet is the ordered character set of the plaintext; its length is the FF1 radix.
// Any 2..62 distinct characters work, e.g. Alphabet("0123456789ABCDEF").
type Alphabet string

const (
	Numeric      Alphabet = digits
	Alpha        Alphabet = letters
	Alphanumeric Alphabet = digits + letters
)

func (a Alphabet) runes() ([]rune, error) {
	r := []rune(string(a))
	seen := map[rune]bool{}
	for _, c := range r {
		if seen[c] {
			return nil, errors.ErrInputInvalid.With("alphabet repeats a character")
		}
		seen[c] = true
	}
	if len(r) < 2 || len(r) > MaxRadix || !utf8.ValidString(string(a)) {
		return nil, errors.ErrInputInvalid.With("alphabet must have 2..62 distinct characters")
	}
	return r, nil
}

// Encrypt returns a string of the same length over the same alphabet.
func Encrypt(key []byte, plaintext string, tweak []byte, alphabet Alphabet) (string, error) {
	return run(key, plaintext, tweak, alphabet, true)
}

// Decrypt is the inverse of Encrypt.
func Decrypt(key []byte, ciphertext string, tweak []byte, alphabet Alphabet) (string, error) {
	return run(key, ciphertext, tweak, alphabet, false)
}

func run(key []byte, in string, tweak []byte, alphabet Alphabet, enc bool) (string, error) {
	if len(key) != KeySize {
		return "", errors.ErrKeySizeInvalid.With("FF1 needs a 32-byte AES-256 key")
	}
	ab, err := alphabet.runes()
	if err != nil {
		return "", err
	}
	idx := make(map[rune]uint16, len(ab))
	for i, c := range ab {
		idx[c] = uint16(i)
	}
	runes := []rune(in)
	x := make([]uint16, len(runes))
	for i, c := range runes {
		v, ok := idx[c]
		if !ok {
			return "", errors.ErrInputCharOutsideAlphabet
		}
		x[i] = v
	}
	if float64(len(x))*math.Log10(float64(len(ab))) < 6 {
		return "", errors.ErrInputInvalid.With("domain smaller than 10^6: input too short for this alphabet")
	}
	y, err := raw(key, len(ab), tweak, x, enc)
	if err != nil {
		return "", err
	}
	out := make([]rune, len(y))
	for i, v := range y {
		out[i] = ab[v]
	}
	return string(out), nil
}

// raw runs FF1 encrypt (SP 800-38G Algorithm 7) or decrypt (Algorithm 8) on numerals x in
// base radix, with an AES-128/192/256 key (all three for NIST vectors).
func raw(key []byte, radix int, tweak []byte, x []uint16, enc bool) ([]uint16, error) {
	if radix < 2 || radix > MaxRadix || len(x) < 2 || len(x) > MaxLen || len(tweak) > MaxTweak {
		return nil, errors.ErrInputInvalid.With("FF1 parameters out of range")
	}
	s := make([]byte, len(x))
	for i, v := range x {
		if int(v) >= radix {
			return nil, errors.ErrInputCharOutsideAlphabet
		}
		s[i] = numerals[v]
	}
	c, err := capitalone.NewCipher(radix, MaxTweak, key, tweak)
	if err != nil {
		return nil, errors.ErrInputInvalid.With("FF1: " + err.Error())
	}
	var out string
	if enc {
		out, err = c.Encrypt(string(s))
	} else {
		out, err = c.Decrypt(string(s))
	}
	if err != nil || len(out) != len(x) {
		return nil, errors.ErrInputInvalid.With("FF1 failed")
	}
	y := make([]uint16, len(out))
	for i := range out {
		y[i] = uint16(strings.IndexByte(numerals, out[i])) //nolint:gosec // out is in the alphabet (radix <= 62)
	}
	return y, nil
}
