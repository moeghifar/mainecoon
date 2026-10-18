// Package vectors loads JSON test-vector files in tests.
package vectors

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Load decodes the JSON file at path into v.
func Load(t testing.TB, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// Hex is a hex string that decodes itself when unmarshalled.
type Hex []byte

func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

// MustHex decodes s or panics (constants in tests).
func MustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
