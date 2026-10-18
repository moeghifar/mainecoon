# mainecoon

Cryptographic primitives for Go, grouped by use case. Every algorithm is a call into the Go
standard library, `golang.org/x/crypto`, `cloudflare/circl`, `tink-crypto/tink-go` or
`capitalone/fpe`. Nothing is hand-written. Each one is checked against official test vectors
and a startup self-test.

mainecoon is a library only. It has no servers, storage, KMS clients or envelope formats.
Those belong to the application that imports it.

## Install

```sh
go get github.com/moeghifar/mainecoon@v0.1.0
```

Requires **Go 1.27** (use the latest patch release). ML-KEM, ML-DSA, SLH-DSA and HPKE come
from the standard library in 1.27, so they run natively and inside the Go FIPS 140-3 module
where Go supports it.

## API shape

Every package follows the same pattern:

- the key comes first and `aad` comes last;
- one ciphertext value comes out, with the nonce, encapsulation and tag inside it;
- there is an algorithm argument only where there is a real choice.

Nonces are generated inside the library. `Verify` returns `nil` or `VERIFICATION_FAILED`.
`Decrypt` returns `DECRYPTION_FAILED`.

## How to

### Encrypt data (AEAD)

```go
import "github.com/moeghifar/mainecoon/symmetric/aead"

key, _ := drbg.Bytes(aead.KeySize)
ct, err := aead.Encrypt(aead.AES256GCM, key, plaintext, []byte("tenant-42"))
pt, err := aead.Decrypt(aead.AES256GCM, key, ct, []byte("tenant-42"))
```

Pass the aad **you expect** to `Decrypt`, never a value read from the stored record.
Otherwise a record copied from another tenant would decrypt.

### Store ciphertext as text (token)

```go
import "github.com/moeghifar/mainecoon/token"

tok, _ := token.Encrypt("aes-gcm-256", key, 3, pt, aad) // mc:aes-gcm-256:v3:<base64>
pt, _  := token.Decrypt(func(v uint32) ([]byte, error) { return keyring[v], nil }, tok, aad)
```

The header (algorithm and key version) is bound into the AAD, so editing it breaks
decryption. The codes are `aes-gcm-256`, `chacha20-poly1305` and `aes-siv-256`.

### Encrypt a large file (streaming)

```go
import "github.com/moeghifar/mainecoon/symmetric/stream"

w, _ := stream.Encrypt(key, out, aad)
io.Copy(w, in)
w.Close() // required: writes the final segment

r, _ := stream.Decrypt(key, in, aad)
io.Copy(out, r)
```

### Sign and verify (post-quantum)

```go
import "github.com/moeghifar/mainecoon/asymmetric/sign"

pk, sk, _ := sign.GenerateKey(sign.MLDSA65)
sig, _    := sign.Sign(sign.MLDSA65, sk, msg)
err       := sign.Verify(sign.MLDSA65, pk, msg, sig) // nil or VERIFICATION_FAILED
```

### Encrypt to a public key (HPKE)

```go
import "github.com/moeghifar/mainecoon/asymmetric/hpke"

pk, sk, _ := hpke.GenerateKey(hpke.Hybrid) // ML-KEM-768 + P-256
ct, _ := hpke.Encrypt(hpke.Hybrid, pk, pt, aad)
pt, _ := hpke.Decrypt(hpke.Hybrid, sk, ct, aad)
```

### Agree on a shared secret (KEM)

```go
import "github.com/moeghifar/mainecoon/asymmetric/kem"

ct, ss, _ := kem.Encapsulate(kem.MLKEM768, pk) // sender
ss, _     := kem.Decapsulate(kem.MLKEM768, sk, ct) // recipient
```

### Hash and verify passwords

```go
import "github.com/moeghifar/mainecoon/password"

enc, _ := password.Hash("Argon2id", pw, password.Params{}) // zero Params = floor values
ok, _  := password.Verify(pw, enc)
```

Verifying Argon2id costs up to 256 MiB of memory. If stored hashes can come from requests,
limit how many `Verify` calls run at once.

### Encode keys

```go
import "github.com/moeghifar/mainecoon/keys"

s, _  := keys.Encode("ML-DSA-65", pk, false, keys.PEM)
pk, _ := keys.Decode("ML-DSA-65", s, false, keys.PEM)
```

The formats are `RAW_HEX`, `RAW_BASE64` (base64url), `PEM` (PKCS#8/PKIX) and `JWK` (EC, OKP,
RSA, AKP).

### Run the startup self-test

```go
import "github.com/moeghifar/mainecoon/kat"

if err := kat.Err(kat.Run(nil)); err != nil {
	log.Fatal(err) // KAT_FAILURE: refuse to serve
}
```

`kat.Run(permitted)` skips the algorithms that your policy does not allow.

### Handle errors

```go
import mcerr "github.com/moeghifar/mainecoon/errors"

if mcerr.Is(err, mcerr.ErrDecryptionFailed) { /* ... */ }
```

`Error()` returns only the code (`DECRYPTION_FAILED`, `KEY_SIZE_INVALID`, …). Internal detail
is in `Detail()`, for logs.

## Algorithms

FIPS means NIST-approved for that use. Only standard-library code runs inside Go's validated
FIPS 140-3 module.

| Package | Algorithms | Standard |
|---|---|---|
| `symmetric/aead` | AES-256-GCM, ChaCha20-Poly1305 | SP 800-38D, RFC 8439 |
| `symmetric/siv` | AES-256-SIV (deterministic) | RFC 5297 (not FIPS) |
| `symmetric/xts` | AES-256-XTS | SP 800-38E |
| `symmetric/kwp` | AES-256-KWP | SP 800-38F |
| `symmetric/ff1` | FF1 (format-preserving) | SP 800-38G Rev 1 |
| `symmetric/stream` | AES-256-GCM-HKDF-1MB | Tink streaming AEAD |
| `symmetric/cmac`, `gmac` | AES-256-CMAC, AES-256-GMAC | SP 800-38B, 38D |
| `asymmetric/sign` | ECDSA P-256/384/521, Ed25519, Ed448, RSA-PSS-2048/3072/4096, ML-DSA-44/65/87, SLH-DSA-SHA2-128s | FIPS 186-5, 204, 205 |
| `asymmetric/kem` | ML-KEM-512/768/1024, DHKEM P-256/384/521/X25519, X-Wing, X25519+ML-KEM-768 | FIPS 203, RFC 9180 |
| `asymmetric/hpke` | Classic, X25519, Hybrid, XWing, MLKEM768, MLKEM1024 | RFC 9180, draft-ietf-hpke-pq |
| `asymmetric/rsaoaep` | RSA-OAEP-2048/3072/4096 | SP 800-56B Rev 2 |
| `hash` | SHA-2, SHA-3, SHAKE128/256 | FIPS 180-4, 202 |
| `mac` | HMAC-SHA256/384/512, HMAC-SHA3-256 | FIPS 198-1 |
| `kdf` | HKDF-SHA256/384/512 | RFC 5869 |
| `password` | PBKDF2, Argon2id, scrypt, bcrypt | SP 800-132, RFC 9106 |
| `drbg` | `crypto/rand` (CTR_DRBG) | SP 800-90A |

Each `registry` entry carries a `Strength` in bits, so callers can enforce a floor. The default
floor is 128 bits, so RSA-2048 (112 bits) needs an explicit opt-in.

**Rejected** (`ALGO_DISABLED`): MD5, SHA-1, 3DES, AES-CBC/ECB/CTR, RSA-PKCS1-v1.5, DSA,
FF3-1 (withdrawn by NIST) and AES-KW (use KWP). RSA below 2048 bits returns
`PARAM_BELOW_FLOOR`.

## Assurance

- **Startup KAT:** 58 known-answer tests. The build fails if a registry algorithm has none.
- **Official vectors:** NIST ACVP, C2SP Wycheproof, RFCs and IEEE 1619. The source of each
  vector is noted in its `testdata/`.
- **Fuzzing:** every parser that reads untrusted input (tokens, PEM/JWK, key unwrap, SIV,
  stored password hashes).
- **CI:** vet, race, `GODEBUG=fips140=only`, staticcheck, govulncheck, fuzz smoke.

```sh
go test ./...                                              # all
go test -short ./...                                       # skip slow PBKDF2
GODEBUG=fips140=only go test -run TestFIPSOnlyModule ./kat
```

## Contributing

Read [AGENTS.md](AGENTS.md) first. It applies to people and AI agents alike. Release steps are
in [RELEASING.md](RELEASING.md). Report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
