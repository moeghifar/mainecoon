package hash

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
)

// UT-HASH-001..005 (FIPS 180-4 / FIPS 202 "abc"), 009 (empty input).
func TestVectors(t *testing.T) {
	for alg, want := range map[string]string{
		"SHA-256":  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"SHA-384":  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		"SHA-512":  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"SHA3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		"SHA3-384": "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
		"SHA3-512": "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	} {
		got, err := Sum(alg, []byte("abc"))
		if err != nil || hex.EncodeToString(got) != want {
			t.Errorf("%s: %x %v", alg, got, err)
		}
	}
	e, _ := Sum("SHA-256", nil)
	if hex.EncodeToString(e) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty input")
	}
}

// UT-HASH-006: SHAKE variable output; prefixes agree.
func TestXOF(t *testing.T) {
	want := "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
	got, _ := XOF("SHAKE256", nil, 64)
	if hex.EncodeToString(got) != want {
		t.Fatalf("SHAKE256(\"\"): %x", got)
	}
	for _, n := range []int{32, 128} {
		o, _ := XOF("SHAKE256", nil, n)
		if len(o) != n || !bytes.Equal(o[:32], got[:32]) {
			t.Fatal("prefix mismatch")
		}
	}
	s, _ := XOF("SHAKE128", nil, 32)
	if hex.EncodeToString(s) != "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26" {
		t.Fatal("SHAKE128")
	}
	if _, err := XOF("SHAKE256", nil, 8); !errors.Is(err, errors.ErrInputInvalid) {
		t.Fatal("8-byte output accepted")
	}
}

// UT-HASH-007, 008, 010.
func TestDisabledAndStreaming(t *testing.T) {
	for _, alg := range []string{"SHA-1", "MD5"} {
		if _, err := Sum(alg, nil); !errors.Is(err, errors.ErrAlgorithmDisabled) {
			t.Fatal(alg, "not disabled")
		}
	}
	data := strings.Repeat("peruri ", 10000)
	a, _ := Sum("SHA3-256", []byte(data))
	b, _ := SumReader("SHA3-256", strings.NewReader(data))
	if !bytes.Equal(a, b) {
		t.Fatal("streaming differs")
	}
}
