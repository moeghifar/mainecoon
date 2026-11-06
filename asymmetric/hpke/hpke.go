// Package hpke is single-shot Hybrid Public Key Encryption (RFC 9180) from the Go stdlib:
//
//	pk, sk, _ := hpke.GenerateKey(hpke.Hybrid)
//	ct, _     := hpke.Encrypt(hpke.Hybrid, pk, pt, aad)   // enc ‖ ciphertext ‖ tag
//	pt, _     := hpke.Decrypt(hpke.Hybrid, sk, ct, aad)
//
// Suites:
//
//	HPKE-Classic  DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM            enc 65 bytes
//	HPKE-Hybrid   MLKEM768-P256 + HKDF-SHA384 + AES-256-GCM (PQ)      enc 1153 bytes
//	HPKE-XWing    MLKEM768-X25519 (X-Wing) + HKDF-SHA256 + AES-256-GCM (PQ)  enc 1120 bytes
//	HPKE-X25519   DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM                 enc 32 bytes
//	HPKE-MLKEM768 ML-KEM-768 + HKDF-SHA256 + AES-256-GCM (PQ only)          enc 1088 bytes
//	HPKE-MLKEM1024 ML-KEM-1024 + HKDF-SHA384 + AES-256-GCM (PQ only)        enc 1568 bytes
//
// The ML-KEM hybrid KEMs follow draft-ietf-hpke-pq as implemented by Go's crypto/hpke.
//
// The ciphertext is one value: the KEM encapsulation, then the AEAD output. info is fixed
// to Info so a ciphertext cannot be replayed into another protocol; the *WithInfo functions
// take a caller-chosen info for interop. SenderExport/ReceiverExport derive a shared secret
// (RFC 9180 §5.3, base mode) instead of encrypting.
package hpke

import (
	"crypto/ecdh"
	stdhpke "crypto/hpke"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/reg"
)

// Info is the HPKE info string for every mainecoon ciphertext.
const Info = "mainecoon/hpke/v1"

// Alg names an HPKE suite. Its value is the registry ID.
type Alg string

const (
	Classic   Alg = "HPKE-Classic"
	Hybrid    Alg = "HPKE-Hybrid"
	XWing     Alg = "HPKE-XWing"
	X25519    Alg = "HPKE-X25519"
	MLKEM768  Alg = "HPKE-MLKEM768"
	MLKEM1024 Alg = "HPKE-MLKEM1024"
)

type suite struct {
	kem     stdhpke.KEM
	kdf     stdhpke.KDF
	aead    stdhpke.AEAD
	encSize int
}

var suites = map[string]suite{
	string(Classic):   {stdhpke.DHKEM(ecdh.P256()), stdhpke.HKDFSHA256(), stdhpke.AES256GCM(), 65},
	string(Hybrid):    {stdhpke.MLKEM768P256(), stdhpke.HKDFSHA384(), stdhpke.AES256GCM(), 1088 + 65},
	string(XWing):     {stdhpke.MLKEM768X25519(), stdhpke.HKDFSHA256(), stdhpke.AES256GCM(), 1088 + 32},
	string(X25519):    {stdhpke.DHKEM(ecdh.X25519()), stdhpke.HKDFSHA256(), stdhpke.AES256GCM(), 32},
	string(MLKEM768):  {stdhpke.MLKEM768(), stdhpke.HKDFSHA256(), stdhpke.AES256GCM(), 1088},
	string(MLKEM1024): {stdhpke.MLKEM1024(), stdhpke.HKDFSHA384(), stdhpke.AES256GCM(), 1568},
}

// GenerateKey returns a new recipient key pair.
func GenerateKey(alg Alg) (pk, sk []byte, err error) {
	s, err := reg.Lookup(suites, string(alg))
	if err != nil {
		return nil, nil, err
	}
	k, err := s.kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	sk, err = k.Bytes()
	return k.PublicKey().Bytes(), sk, err
}

// Public derives the public key from a private key.
func Public(alg Alg, sk []byte) ([]byte, error) {
	s, err := reg.Lookup(suites, string(alg))
	if err != nil {
		return nil, err
	}
	k, err := s.kem.NewPrivateKey(sk)
	if err != nil {
		return nil, errors.ErrKeyFormatInvalid
	}
	return k.PublicKey().Bytes(), nil
}

// Encrypt seals pt to the recipient public key and returns enc ‖ ciphertext.
func Encrypt(alg Alg, recipientPK, pt, aad []byte) ([]byte, error) {
	return EncryptWithInfo(alg, recipientPK, []byte(Info), pt, aad)
}

// EncryptWithInfo is Encrypt with a caller-chosen info string, for interop with other HPKE
// implementations. Use Encrypt otherwise.
func EncryptWithInfo(alg Alg, recipientPK, info, pt, aad []byte) ([]byte, error) {
	return encrypt(alg, recipientPK, info, pt, aad)
}

// Decrypt opens enc ‖ ciphertext. Any failure is ErrDecryptionFailed.
func Decrypt(alg Alg, recipientSK, ct, aad []byte) ([]byte, error) {
	return decrypt(alg, recipientSK, []byte(Info), ct, aad)
}

func encrypt(alg Alg, recipientPK, info, pt, aad []byte) ([]byte, error) {
	s, err := reg.Lookup(suites, string(alg))
	if err != nil {
		return nil, err
	}
	pk, err := s.kem.NewPublicKey(recipientPK)
	if err != nil {
		return nil, errors.ErrKeyFormatInvalid
	}
	enc, snd, err := stdhpke.NewSender(pk, s.kdf, s.aead, info)
	if err != nil {
		return nil, err
	}
	ct, err := snd.Seal(aad, pt)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// DecryptWithInfo is Decrypt with a caller-chosen info string, for interop and RFC 9180
// known-answer tests. Use Decrypt otherwise.
func DecryptWithInfo(alg Alg, recipientSK, info, ct, aad []byte) ([]byte, error) {
	return decrypt(alg, recipientSK, info, ct, aad)
}

func decrypt(alg Alg, recipientSK, info, in, aad []byte) ([]byte, error) {
	s, err := reg.Lookup(suites, string(alg))
	if err != nil {
		return nil, err
	}
	sk, err := s.kem.NewPrivateKey(recipientSK)
	if err != nil {
		return nil, errors.ErrKeyFormatInvalid
	}
	if len(in) < s.encSize+16 {
		return nil, errors.ErrCiphertextEmpty
	}
	r, err := stdhpke.NewRecipient(in[:s.encSize], sk, s.kdf, s.aead, info)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	pt, err := r.Open(aad, in[s.encSize:])
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}
	return pt, nil
}

// SenderExport derives a length-byte secret shared with the holder of recipientPK (RFC 9180
// §5.3, base mode). Send enc to the recipient, who calls ReceiverExport with the same info
// and exporterContext. length must be in 1..255*Nh (8160 for HKDF-SHA256 suites, 12240 for
// HKDF-SHA384 suites), else ErrInputInvalid.
func SenderExport(alg Alg, recipientPK, info, exporterContext []byte, length int) (enc, secret []byte, err error) {
	s, err := reg.Lookup(suites, string(alg))
	if err != nil {
		return nil, nil, err
	}
	if err := checkExportLen(s, length); err != nil {
		return nil, nil, err
	}
	pk, err := s.kem.NewPublicKey(recipientPK)
	if err != nil {
		return nil, nil, errors.ErrKeyFormatInvalid
	}
	enc, snd, err := stdhpke.NewSender(pk, s.kdf, s.aead, info)
	if err != nil {
		return nil, nil, err
	}
	secret, err = snd.Export(string(exporterContext), length)
	if err != nil {
		return nil, nil, err
	}
	return enc, secret, nil
}

// ReceiverExport derives the secret SenderExport returned, from its enc and the recipient
// private key. A malformed enc is ErrInputInvalid; one that fails to decapsulate is
// ErrDecapsulationFailed.
func ReceiverExport(alg Alg, recipientSK, enc, info, exporterContext []byte, length int) ([]byte, error) {
	s, err := reg.Lookup(suites, string(alg))
	if err != nil {
		return nil, err
	}
	if err := checkExportLen(s, length); err != nil {
		return nil, err
	}
	sk, err := s.kem.NewPrivateKey(recipientSK)
	if err != nil {
		return nil, errors.ErrKeyFormatInvalid
	}
	if len(enc) != s.encSize {
		return nil, errors.ErrInputInvalid
	}
	r, err := stdhpke.NewRecipient(enc, sk, s.kdf, s.aead, info)
	if err != nil {
		return nil, errors.ErrDecapsulationFailed
	}
	return r.Export(string(exporterContext), length)
}

// checkExportLen enforces RFC 9180 §5.3: 0 < L <= 255*Nh.
func checkExportLen(s suite, length int) error {
	nh := 32 // HKDF-SHA256
	if s.kdf.ID() == stdhpke.HKDFSHA384().ID() {
		nh = 48
	}
	if length < 1 || length > 255*nh {
		return errors.ErrInputInvalid
	}
	return nil
}
