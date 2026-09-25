package strsim

import (
	"github.com/antlabs/strsim/similarity"
)

// Compare returns the similarity of two strings.
func Compare(s1, s2 string, opts ...Option) float64 {
	var o option

	o.fillOption(opts...)

	return compare(s1, s2, &o)
}

// FindBestMatchOne returns the string with the highest similarity.
func FindBestMatchOne(s string, targets []string, opts ...Option) *similarity.Match {
	r := findBestMatch(s, targets, opts...)
	return r.Match
}

// FindBestMatch returns the string with the highest similarity and its index.
func FindBestMatch(s string, targets []string, opts ...Option) *similarity.MatchResult {
	return findBestMatch(s, targets, opts...)
}
