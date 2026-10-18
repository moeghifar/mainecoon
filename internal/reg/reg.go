// Package reg holds the lookup helpers shared by the algorithm packages.
package reg

import (
	"slices"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/registry"
)

// Lookup returns m[id]. An ID the package does not implement returns the policy
// registry's error (ErrParameterBelowFloor, ErrAlgorithmDisabled) or, for an approved
// algorithm of another family, ErrAlgorithmDisabled.
func Lookup[T any](m map[string]T, id string) (T, error) {
	if v, ok := m[id]; ok {
		return v, nil
	}
	var zero T
	if _, err := registry.Lookup(id); err != nil {
		return zero, err
	}
	return zero, errors.ErrAlgorithmDisabled.With(id + " is not a member of this family")
}

// IDs returns the sorted keys of a registry.
func IDs[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
