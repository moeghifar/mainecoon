package kat

import (
	"testing"

	"github.com/moeghifar/mainecoon/registry"
)

func TestAllPass(t *testing.T) {
	rs := Run(nil)
	for _, r := range rs {
		if !r.Passed {
			t.Errorf("%s %s (%s): %s", r.ID, r.Algorithm, r.Name, r.Detail)
		}
	}
	if !Passed(rs) || Err(rs) != nil {
		t.Fatal("self-test failed")
	}
}

// Every approved algorithm has at least one known-answer test.
func TestCoverage(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range tests {
		covered[tc.alg] = true
		if _, err := registry.Lookup(tc.alg); err != nil {
			t.Errorf("%s tests unknown algorithm %s", tc.id, tc.alg)
		}
	}
	for _, a := range registry.All() {
		if !covered[a.ID] && a.Family != registry.PasswordKDF && a.Family != registry.PasswordHash {
			t.Errorf("no KAT for %s", a.ID)
		}
	}
}

func TestFailureIsReported(t *testing.T) {
	saved := tests
	defer func() { tests = saved }()
	tests = append([]test{{"KAT-X", "SHA-256", "broken", digest("SHA-256", "00")}}, saved...)
	rs := Run(nil)
	if Passed(rs) || Err(rs) == nil {
		t.Fatal("broken vector not detected")
	}
}
