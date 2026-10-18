// Package password derives keys from passwords (cryptop F11) and hashes passwords
// for storage (F12). Every algorithm has a security floor and an upper bound, so a
// caller (or an attacker-supplied hash string) can neither weaken nor exhaust it.
package password

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/moeghifar/mainecoon/drbg"
	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Params tunes the work factor. Zero fields take the floor value.
type Params struct {
	Iterations  int    `json:"iterations,omitempty"`  // PBKDF2; Argon2id time cost
	MemoryKiB   uint32 `json:"memory_kib,omitempty"`  // Argon2id
	Parallelism uint8  `json:"parallelism,omitempty"` // Argon2id
	N           int    `json:"n,omitempty"`           // scrypt CPU/memory cost (power of 2)
	R           int    `json:"r,omitempty"`           // scrypt block size
	P           int    `json:"p,omitempty"`           // scrypt parallelism
	Cost        int    `json:"cost,omitempty"`        // bcrypt
}

// Floors (plan F11/F12, core/password VAPT notes) and ceilings (DoS protection).
const (
	PBKDF2SHA256MinIter = 600_000
	PBKDF2SHA384MinIter = 210_000
	PBKDF2MaxIter       = 10_000_000
	ArgonMinTime        = 3
	ArgonMaxTime        = 64
	ArgonMinMemKiB      = 64 * 1024
	ArgonMaxMemKiB      = 256 * 1024 // a stored hash may come from an attacker: cap per-call memory
	ArgonMinPar         = 4
	ArgonMaxPar         = 64
	ScryptMinN          = 1 << 15
	ScryptMaxN          = 1 << 20
	ScryptMaxR          = 32
	ScryptMaxP          = 16
	BcryptMinCost       = 12
	BcryptMaxCost       = 16
	MinSalt             = 16
	MinLength           = 16
	MaxLength           = 512
	MaxPassword         = 4096
)

type kdfFunc func(pw string, salt []byte, p Params, n int) ([]byte, error)

var kdfs = map[string]kdfFunc{
	"PBKDF2-SHA256": func(pw string, salt []byte, p Params, n int) ([]byte, error) {
		it := def(p.Iterations, PBKDF2SHA256MinIter)
		if it < PBKDF2SHA256MinIter || it > PBKDF2MaxIter {
			return nil, errors.ErrIterationsBelowFloor.With("PBKDF2-SHA256 needs 600,000..10,000,000 iterations")
		}
		return pbkdf2.Key(sha256.New, pw, salt, it, n)
	},
	"PBKDF2-SHA384": func(pw string, salt []byte, p Params, n int) ([]byte, error) {
		it := def(p.Iterations, PBKDF2SHA384MinIter)
		if it < PBKDF2SHA384MinIter || it > PBKDF2MaxIter {
			return nil, errors.ErrIterationsBelowFloor.With("PBKDF2-SHA384 needs 210,000..10,000,000 iterations")
		}
		return pbkdf2.Key(sha512.New384, pw, salt, it, n)
	},
	"Argon2id": func(pw string, salt []byte, p Params, n int) ([]byte, error) {
		t, m, par, err := argonParams(p)
		if err != nil {
			return nil, err
		}
		return argon2.IDKey([]byte(pw), salt, t, m, par, uint32(n)), nil
	},
	"scrypt": func(pw string, salt []byte, p Params, n int) ([]byte, error) {
		N, r, par := def(p.N, ScryptMinN), def(p.R, 8), def(p.P, 1)
		if N < ScryptMinN || N > ScryptMaxN || N&(N-1) != 0 || r < 8 || r > ScryptMaxR || par < 1 || par > ScryptMaxP {
			return nil, errors.ErrParameterBelowFloor.With("scrypt needs N power of 2 in 2^15..2^20, r 8..32, p 1..16")
		}
		return scrypt.Key([]byte(pw), salt, N, r, par, n)
	},
}

func def(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

func argonParams(p Params) (t, m uint32, par uint8, err error) {
	it := def(p.Iterations, ArgonMinTime)
	if it < 0 || it > ArgonMaxTime { // check before narrowing: uint32(1<<32+5) == 5
		return 0, 0, 0, errors.ErrParameterBelowFloor.With("Argon2id needs t 3..64, m 64MiB..256MiB, p 4..64")
	}
	t, m, par = uint32(it), p.MemoryKiB, p.Parallelism //nolint:gosec // range checked above
	if m == 0 {
		m = ArgonMinMemKiB
	}
	if par == 0 {
		par = ArgonMinPar
	}
	return t, m, par, argonBounds(t, m, par)
}

// argonBounds checks exact values (no defaults): used for parameters read from a stored hash.
func argonBounds(t, m uint32, par uint8) error {
	if t < ArgonMinTime || t > ArgonMaxTime || m < ArgonMinMemKiB || m > ArgonMaxMemKiB || par < ArgonMinPar || par > ArgonMaxPar {
		return errors.ErrParameterBelowFloor.With("Argon2id needs t 3..64, m 64MiB..256MiB, p 4..64")
	}
	return nil
}

func KDFAlgorithms() []string { return reg.IDs(kdfs) }

// DeriveKey derives length bytes from a password (cryptop F11).
func DeriveKey(alg, password string, salt []byte, p Params, length int) ([]byte, error) {
	f, err := reg.Lookup(kdfs, alg)
	if err != nil {
		return nil, err
	}
	if len(salt) < MinSalt {
		return nil, errors.ErrInputInvalid.With("salt must be at least 16 bytes")
	}
	if length < MinLength || length > MaxLength {
		return nil, errors.ErrInputInvalid.With("length must be 16..512")
	}
	if len(password) == 0 || len(password) > MaxPassword {
		return nil, errors.ErrInputInvalid.With("password must be 1..4096 bytes")
	}
	return f(password, salt, p, length)
}

// Hash returns a self-contained encoded hash (cryptop F12): PHC string for Argon2id,
// $2b$ for bcrypt.
func Hash(alg, password string, p Params) (string, error) {
	if len(password) == 0 || len(password) > MaxPassword {
		return "", errors.ErrInputInvalid.With("password must be 1..4096 bytes")
	}
	switch alg {
	case "Argon2id":
		t, m, par, err := argonParams(p)
		if err != nil {
			return "", err
		}
		salt := make([]byte, MinSalt)
		if err := drbg.Read(salt); err != nil {
			return "", err
		}
		h := argon2.IDKey([]byte(password), salt, t, m, par, 32)
		enc := base64.RawStdEncoding
		return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, t, par, enc.EncodeToString(salt), enc.EncodeToString(h)), nil
	case "bcrypt":
		cost := def(p.Cost, BcryptMinCost)
		if cost < BcryptMinCost || cost > BcryptMaxCost {
			return "", errors.ErrParameterBelowFloor.With("bcrypt cost must be 12..16")
		}
		if len(password) > 72 {
			return "", errors.ErrInputTooLarge.With("bcrypt truncates at 72 bytes; use Argon2id")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
		return string(h), err
	}
	_, err := reg.Lookup(map[string]bool{}, alg)
	return "", err
}

// Verify checks password against an encoded hash in constant time. A wrong password
// is (false, nil); a malformed or out-of-bounds hash is an error.
func Verify(password, encoded string) (bool, error) {
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		var v int
		var m, t uint32
		var par uint8
		parts := strings.Split(encoded, "$")
		if len(parts) != 6 {
			return false, errors.ErrInputInvalid.With("bad argon2id hash")
		}
		if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
			return false, errors.ErrInputInvalid.With("bad argon2id version")
		}
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &par); err != nil {
			return false, errors.ErrInputInvalid.With("bad argon2id params")
		}
		if err := argonBounds(t, m, par); err != nil {
			return false, err
		}
		salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
		want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
		if err1 != nil || err2 != nil || len(salt) < MinSalt || len(want) < 16 || len(want) > 64 {
			return false, errors.ErrInputInvalid.With("bad argon2id salt or hash")
		}
		got := argon2.IDKey([]byte(password), salt, t, m, par, uint32(len(want))) //nolint:gosec // len(want) <= 64, checked above
		return subtle.ConstantTimeCompare(got, want) == 1, nil
	case strings.HasPrefix(encoded, "$2a$"), strings.HasPrefix(encoded, "$2b$"), strings.HasPrefix(encoded, "$2y$"):
		cost, err := bcrypt.Cost([]byte(encoded))
		if err != nil {
			return false, errors.ErrInputInvalid.With("bad bcrypt hash")
		}
		if cost > BcryptMaxCost {
			return false, errors.ErrInputInvalid.With("bcrypt cost above ceiling")
		}
		err = bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
		if err == bcrypt.ErrMismatchedHashAndPassword || err == bcrypt.ErrPasswordTooLong {
			return false, nil
		}
		return err == nil, err
	}
	return false, errors.ErrAlgorithmDisabled.With("unknown password hash format")
}
