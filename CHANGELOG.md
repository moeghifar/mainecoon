# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/);
while the major version is 0, a minor release may change the API.

## [0.1.0] — 2026-10-20

First release.

### Added
- **Symmetric** (`symmetric/`): AES-256-GCM, ChaCha20-Poly1305 (`aead`); AES-256-SIV (`siv`);
  AES-256-XTS (`xts`); AES-256-KWP (`kwp`); FF1 (`ff1`); AES-256-GCM-HKDF streaming
  (`stream`); AES-256-CMAC (`cmac`); AES-256-GMAC (`gmac`).
- **Asymmetric** (`asymmetric/`): ECDSA P-256/384/521, Ed25519, Ed448, RSA-PSS-2048/3072/4096,
  ML-DSA-44/65/87, SLH-DSA-SHA2-128s (`sign`); ML-KEM-512/768/1024, DHKEM P-256/384/521/X25519,
  X-Wing, X25519+ML-KEM-768 (`kem`); HPKE Classic, X25519, Hybrid, XWing, MLKEM768, MLKEM1024
  (`hpke`); RSA-OAEP-2048/3072/4096 (`rsaoaep`).
- `hash` (SHA-2, SHA-3, SHAKE), `mac` (HMAC), `kdf` (HKDF), `password` (PBKDF2, Argon2id,
  scrypt, bcrypt), `drbg` (crypto/rand).
- `token`: text ciphertext `mc:<alg>:v<n>:<base64>` with key versions, header bound to AAD.
- `registry` with `Strength` (bits) per algorithm; `keys` (RAW_HEX, RAW_BASE64, PEM, JWK);
  coded `errors`.
- `kat`: 58 power-on known-answer tests; official vectors (NIST ACVP, Wycheproof, RFCs,
  IEEE 1619) in unit tests; fuzz targets for every untrusted-input parser.

### Security
- No hand-written cryptography: every algorithm is a call into the Go standard library,
  x/crypto, circl, tink-go or capitalone/fpe.
- Internal secret buffers (password bytes, Argon2id output, decoded key DER/JWK) are wiped
  with `clear()` after use; returned keys and secrets are the caller's to wipe.
- Rejected algorithms return `ALGO_DISABLED`: MD5, SHA-1, 3DES, AES-CBC/ECB/CTR,
  RSA-PKCS1-v1.5, DSA, FF3-1, AES-KW.

[0.1.0]: https://github.com/moeghifar/mainecoon/releases/tag/v0.1.0
