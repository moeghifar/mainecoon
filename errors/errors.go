// Package errors is the mainecoon error taxonomy (cryptop plan/features.md).
//
// Every error a mainecoon package returns matches one of the sentinels below with
// errors.Is. Error() returns only the stable code, never key material, plaintext or
// internal detail; Detail is for internal logs only.
package errors

import stderrors "errors"

// Severity classifies the security impact of an error. Internal routing only; never serialised.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// Error is a coded error. Two Errors match under errors.Is when their codes are equal.
type Error struct {
	Severity Severity
	Code     string
	detail   string
}

func (e *Error) Error() string { return e.Code }

// Detail is the internal context given to With. Log it; never return it to a client.
func (e *Error) Detail() string { return e.detail }

// Is makes errors.Is(err, ErrX) true for any Error carrying ErrX's code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// With returns a copy of the sentinel carrying internal detail for logs.
func (e *Error) With(detail string) *Error {
	return &Error{Severity: e.Severity, Code: e.Code, detail: detail}
}

// Is reports whether err matches target (alias of the standard errors.Is).
func Is(err, target error) bool { return stderrors.Is(err, target) }

func def(s Severity, code string) *Error { return &Error{Severity: s, Code: code} }

// Algorithm errors.
var (
	ErrAlgorithmDisabled     = def(SeverityWarning, "ALGO_DISABLED")      // unknown or globally disabled (MD5, 3DES, FF3-1)
	ErrAlgorithmNotPermitted = def(SeverityWarning, "ALGO_NOT_PERMITTED") // not allowed in the current mode
	ErrPQCDisabled           = def(SeverityWarning, "PQC_DISABLED")
	ErrHybridRequired        = def(SeverityWarning, "HYBRID_REQUIRED")
	ErrModeImmutable         = def(SeverityWarning, "MODE_IMMUTABLE")
	ErrSuiteUnknown          = def(SeverityWarning, "SUITE_UNKNOWN")
)

// Key errors.
var (
	ErrKeySizeInvalid   = def(SeverityWarning, "KEY_SIZE_INVALID")
	ErrKeyTooShort      = def(SeverityWarning, "KEY_TOO_SHORT")
	ErrKeyFormatInvalid = def(SeverityWarning, "KEY_FORMAT_INVALID")
	ErrKeyNotFound      = def(SeverityWarning, "KEY_NOT_FOUND")
)

// Input errors.
var (
	ErrParameterBelowFloor        = def(SeverityWarning, "PARAM_BELOW_FLOOR")
	ErrIterationsBelowFloor       = def(SeverityWarning, "ITERATIONS_BELOW_FLOOR")
	ErrCiphertextEmpty            = def(SeverityWarning, "CIPHERTEXT_EMPTY")
	ErrNonceInvalid               = def(SeverityWarning, "NONCE_INVALID")
	ErrTagInvalid                 = def(SeverityWarning, "TAG_INVALID")
	ErrEnvelopeVersionUnsupported = def(SeverityWarning, "ENVELOPE_VERSION_UNSUPPORTED")
	ErrEnvelopeInvalid            = def(SeverityWarning, "ENVELOPE_INVALID")
	ErrInputTooLarge              = def(SeverityWarning, "INPUT_TOO_LARGE")
	ErrInputInvalid               = def(SeverityWarning, "INPUT_INVALID")
	ErrInputCharOutsideAlphabet   = def(SeverityWarning, "CHAR_OUTSIDE_ALPHABET")
	ErrInputBlockUnaligned        = def(SeverityWarning, "INPUT_BLOCK_UNALIGNED")
)

// Crypto operation errors.
var (
	ErrDecryptionFailed    = def(SeverityCritical, "DECRYPTION_FAILED")
	ErrVerificationFailed  = def(SeverityCritical, "VERIFICATION_FAILED")
	ErrDecapsulationFailed = def(SeverityCritical, "DECAPSULATION_FAILED")
	ErrDRBGHealthFailure   = def(SeverityCritical, "DRBG_HEALTH_FAILURE")
	ErrIntegrityFailure    = def(SeverityCritical, "INTEGRITY_FAILURE")
	ErrKATFailure          = def(SeverityCritical, "KAT_FAILURE")
)

// Service errors. Not returned by mainecoon itself; defined here so cryptop and kripton share one taxonomy.
var (
	ErrKMSUnavailable    = def(SeverityCritical, "KMS_UNAVAILABLE")
	ErrLicenseInvalid    = def(SeverityCritical, "LICENSE_INVALID")
	ErrLicenseExpired    = def(SeverityCritical, "LICENSE_EXPIRED")
	ErrModuleNotLicensed = def(SeverityWarning, "MODULE_NOT_LICENSED")
	ErrUnauthorized      = def(SeverityWarning, "UNAUTHORIZED")
	ErrUnauthenticated   = def(SeverityWarning, "UNAUTHENTICATED")
)
