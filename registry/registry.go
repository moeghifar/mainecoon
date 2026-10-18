// Package registry is the list of algorithms mainecoon offers, with the facts callers need
// to build policy on top: family, standard, whether the algorithm is FIPS-approved, and
// whether it is post-quantum or hybrid. It holds no modes, suites or rules; those belong to
// the products (xandi crypto agility, cryptop). Strength lets a product enforce a floor:
// xandi defaults to 128 bits, so RSA-2048 (112) needs an explicit legacy opt-in.
//
// FIPS means the algorithm is NIST-approved for that use. It does not mean the code runs
// inside Go's validated module: tink-go, capitalone/fpe and circl primitives do not.
package registry

import (
	"slices"

	"github.com/moeghifar/mainecoon/errors"
)

// Family groups algorithms by operation.
type Family string

const (
	Hash         Family = "hash"
	XOF          Family = "xof"
	MAC          Family = "mac"
	AEAD         Family = "aead"
	DetAEAD      Family = "aead_det"
	Volume       Family = "volume"
	StreamAEAD   Family = "aead_stream"
	FPE          Family = "fpe"
	KDF          Family = "kdf"
	PasswordKDF  Family = "password_kdf"
	PasswordHash Family = "password_hash"
	Signature    Family = "signature"
	KEM          Family = "kem"
	KeyTransport Family = "key_transport"
	HPKE         Family = "hpke"
	KeyWrap      Family = "key_wrap"
	Random       Family = "random"
)

// Info describes one algorithm.
type Info struct {
	ID       string `json:"id"`
	Family   Family `json:"family"`
	Standard string `json:"standard"`
	FIPS     bool   `json:"fips"`         // NIST-approved for this use
	PQ       bool   `json:"post_quantum"` // contains a post-quantum component
	Hybrid   bool   `json:"hybrid"`       // classical + post-quantum
	Strength int    `json:"strength"`     // security bits (SP 800-57; PQC categories 1/3/5 = 128/192/256), 0 = not applicable
	Warning  string `json:"warning,omitempty"`
}

// Asymmetric reports whether the algorithm is a public-key operation.
func (i Info) Asymmetric() bool {
	return i.Family == Signature || i.Family == KEM || i.Family == HPKE || i.Family == KeyTransport
}

var algorithms = []Info{
	{ID: "AES-256-GCM", Family: AEAD, Standard: "FIPS 197 + SP 800-38D", FIPS: true, Strength: 256},
	{ID: "ChaCha20-Poly1305", Family: AEAD, Standard: "RFC 8439", Strength: 256},
	{ID: "AES-256-SIV", Family: DetAEAD, Standard: "RFC 5297", Strength: 256},
	{ID: "AES-256-XTS", Family: Volume, Standard: "FIPS 197 + SP 800-38E", FIPS: true, Strength: 256},
	{ID: "AES-256-GCM-HKDF-1MB", Family: StreamAEAD, Standard: "SP 800-38D + RFC 5869 (Tink streaming AEAD)", Strength: 256},
	{ID: "FF1", Family: FPE, Standard: "SP 800-38G Rev 1", FIPS: true, Strength: 128, Warning: "security also depends on the domain size (minimum 10^6)"},
	{ID: "AES-256-KWP", Family: KeyWrap, Standard: "SP 800-38F + RFC 5649", FIPS: true, Strength: 256},
	{ID: "AES-256-CMAC", Family: MAC, Standard: "SP 800-38B", FIPS: true, Strength: 256},
	{ID: "AES-256-GMAC", Family: MAC, Standard: "SP 800-38D", FIPS: true, Strength: 256},

	{ID: "SHA-256", Family: Hash, Standard: "FIPS 180-4", FIPS: true, Strength: 128},
	{ID: "SHA-384", Family: Hash, Standard: "FIPS 180-4", FIPS: true, Strength: 192},
	{ID: "SHA-512", Family: Hash, Standard: "FIPS 180-4", FIPS: true, Strength: 256},
	{ID: "SHA3-256", Family: Hash, Standard: "FIPS 202", FIPS: true, Strength: 128},
	{ID: "SHA3-384", Family: Hash, Standard: "FIPS 202", FIPS: true, Strength: 192},
	{ID: "SHA3-512", Family: Hash, Standard: "FIPS 202", FIPS: true, Strength: 256},
	{ID: "SHAKE128", Family: XOF, Standard: "FIPS 202", FIPS: true, Strength: 128},
	{ID: "SHAKE256", Family: XOF, Standard: "FIPS 202", FIPS: true, Strength: 256},

	{ID: "HMAC-SHA256", Family: MAC, Standard: "FIPS 198-1", FIPS: true, Strength: 256},
	{ID: "HMAC-SHA384", Family: MAC, Standard: "FIPS 198-1", FIPS: true, Strength: 256},
	{ID: "HMAC-SHA512", Family: MAC, Standard: "FIPS 198-1", FIPS: true, Strength: 256},
	{ID: "HMAC-SHA3-256", Family: MAC, Standard: "FIPS 198-1 + FIPS 202", FIPS: true, Strength: 256},

	{ID: "HKDF-SHA256", Family: KDF, Standard: "RFC 5869 + SP 800-56C", FIPS: true, Strength: 256},
	{ID: "HKDF-SHA384", Family: KDF, Standard: "RFC 5869 + SP 800-56C", FIPS: true, Strength: 256},
	{ID: "HKDF-SHA512", Family: KDF, Standard: "RFC 5869 + SP 800-56C", FIPS: true, Strength: 256},

	{ID: "PBKDF2-SHA256", Family: PasswordKDF, Standard: "SP 800-132", FIPS: true},
	{ID: "PBKDF2-SHA384", Family: PasswordKDF, Standard: "SP 800-132", FIPS: true},
	{ID: "Argon2id", Family: PasswordKDF, Standard: "RFC 9106"},
	{ID: "scrypt", Family: PasswordKDF, Standard: "RFC 7914"},
	{ID: "bcrypt", Family: PasswordHash, Standard: "OpenBSD bcrypt", Warning: "passwords longer than 72 bytes are rejected"},

	{ID: "ECDSA-P256", Family: Signature, Standard: "FIPS 186-5", FIPS: true, Strength: 128},
	{ID: "ECDSA-P384", Family: Signature, Standard: "FIPS 186-5", FIPS: true, Strength: 192},
	{ID: "ECDSA-P521", Family: Signature, Standard: "FIPS 186-5", FIPS: true, Strength: 256},
	{ID: "Ed25519", Family: Signature, Standard: "FIPS 186-5 + RFC 8032", FIPS: true, Strength: 128},
	{ID: "Ed448", Family: Signature, Standard: "FIPS 186-5 + RFC 8032", FIPS: true, Strength: 224},
	{ID: "RSA-PSS-2048", Family: Signature, Standard: "FIPS 186-5", FIPS: true, Strength: 112, Warning: "112-bit: deprecated after 2030 (NIST IR 8547)"},
	{ID: "RSA-PSS-3072", Family: Signature, Standard: "FIPS 186-5", FIPS: true, Strength: 128},
	{ID: "RSA-PSS-4096", Family: Signature, Standard: "FIPS 186-5", FIPS: true, Strength: 152},
	{ID: "ML-DSA-44", Family: Signature, Standard: "FIPS 204", FIPS: true, PQ: true, Strength: 128},
	{ID: "ML-DSA-65", Family: Signature, Standard: "FIPS 204", FIPS: true, PQ: true, Strength: 192},
	{ID: "ML-DSA-87", Family: Signature, Standard: "FIPS 204", FIPS: true, PQ: true, Strength: 256},
	{ID: "SLH-DSA-SHA2-128s", Family: Signature, Standard: "FIPS 205", FIPS: true, PQ: true, Strength: 128},

	{ID: "ECDH-P256", Family: KEM, Standard: "SP 800-56A + RFC 9180 DHKEM", FIPS: true, Strength: 128},
	{ID: "ECDH-P384", Family: KEM, Standard: "SP 800-56A + RFC 9180 DHKEM", FIPS: true, Strength: 192},
	{ID: "ECDH-P521", Family: KEM, Standard: "SP 800-56A + RFC 9180 DHKEM", FIPS: true, Strength: 256},
	{ID: "X25519", Family: KEM, Standard: "RFC 7748 + RFC 9180 DHKEM", Strength: 128},
	{ID: "ML-KEM-512", Family: KEM, Standard: "FIPS 203", FIPS: true, PQ: true, Strength: 128},
	{ID: "ML-KEM-768", Family: KEM, Standard: "FIPS 203", FIPS: true, PQ: true, Strength: 192},
	{ID: "ML-KEM-1024", Family: KEM, Standard: "FIPS 203", FIPS: true, PQ: true, Strength: 256},
	{ID: "X-Wing", Family: KEM, Standard: "draft-connolly-cfrg-xwing-kem (ML-KEM-768 + X25519)", PQ: true, Hybrid: true, Strength: 192},
	{ID: "X25519+ML-KEM-768", Family: KEM, Standard: "FIPS 203 + RFC 7748 (X25519MLKEM768, TLS hybrid)", PQ: true, Hybrid: true, Strength: 192},

	{ID: "RSA-OAEP-2048", Family: KeyTransport, Standard: "SP 800-56B Rev 2 + RFC 8017 (SHA-256)", FIPS: true, Strength: 112, Warning: "112-bit: deprecated after 2030 (NIST IR 8547)"},
	{ID: "RSA-OAEP-3072", Family: KeyTransport, Standard: "SP 800-56B Rev 2 + RFC 8017 (SHA-256)", FIPS: true, Strength: 128},
	{ID: "RSA-OAEP-4096", Family: KeyTransport, Standard: "SP 800-56B Rev 2 + RFC 8017 (SHA-256)", FIPS: true, Strength: 152},

	{ID: "HPKE-Classic", Family: HPKE, Standard: "RFC 9180 DHKEM(P-256)+HKDF-SHA256+AES-256-GCM", FIPS: true, Strength: 128},
	{ID: "HPKE-Hybrid", Family: HPKE, Standard: "RFC 9180 + draft-ietf-hpke-pq MLKEM768-P256+HKDF-SHA384+AES-256-GCM", FIPS: true, PQ: true, Hybrid: true, Strength: 192},
	{ID: "HPKE-XWing", Family: HPKE, Standard: "RFC 9180 + draft-ietf-hpke-pq MLKEM768-X25519+HKDF-SHA256+AES-256-GCM", PQ: true, Hybrid: true, Strength: 192},
	{ID: "HPKE-X25519", Family: HPKE, Standard: "RFC 9180 DHKEM(X25519)+HKDF-SHA256+AES-256-GCM", Strength: 128},
	{ID: "HPKE-MLKEM768", Family: HPKE, Standard: "RFC 9180 + draft-ietf-hpke-pq ML-KEM-768+HKDF-SHA256+AES-256-GCM", FIPS: true, PQ: true, Strength: 192},
	{ID: "HPKE-MLKEM1024", Family: HPKE, Standard: "RFC 9180 + draft-ietf-hpke-pq ML-KEM-1024+HKDF-SHA384+AES-256-GCM", FIPS: true, PQ: true, Strength: 256},

	{ID: "CTR_DRBG-AES256", Family: Random, Standard: "SP 800-90A (Go crypto/rand)", FIPS: true, Strength: 256},
}

var byID = func() map[string]Info {
	m := make(map[string]Info, len(algorithms))
	for _, a := range algorithms {
		m[a.ID] = a
	}
	return m
}()

// belowFloor are real algorithms rejected as too weak (ErrParameterBelowFloor).
var belowFloor = map[string]bool{"RSA-PSS-1024": true, "RSA-OAEP-1024": true}

// Lookup returns the entry for id: ErrParameterBelowFloor for a known-weak parameter set,
// ErrAlgorithmDisabled for anything else not listed.
func Lookup(id string) (Info, error) {
	if i, ok := byID[id]; ok {
		return i, nil
	}
	if belowFloor[id] {
		return Info{}, errors.ErrParameterBelowFloor.With(id)
	}
	return Info{}, errors.ErrAlgorithmDisabled.With(id)
}

// All returns every algorithm, in registry order.
func All() []Info { return slices.Clone(algorithms) }
