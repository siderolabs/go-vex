// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1

import (
	"fmt"
	"regexp"

	"github.com/siderolabs/go-vex/pkg/gitversion"
	"github.com/siderolabs/go-vex/pkg/kernelversion"
)

// Expand converts a Statement into one or more Statement values, one per
// entry in VersionRanges. When VersionRanges is empty, the statement passes
// through unchanged.
//
// Each entry is one of:
//
//	">= vX.Y.Z"            → from = vX.Y.Z, to = ""    (forward, unbounded above)
//	">= vX.Y.Z < vA.B.C"   → from = vX.Y.Z, to = vA.B.C (upper bound is exclusive)
//
// Statement.To is interpreted as an exclusive upper bound throughout the
// versionRanges path; vexgen filters via gitversion.VersionInRangeExclusive.
//
// Entries are checked pair-wise for overlap. VersionRanges cannot be combined
// with explicit From/To.
//
// KernelVersionRanges is deliberately not expanded. Those ranges describe a
// single kernel version axis rather than distinct Talos release lines, so the
// statement is carried through intact and matched as a whole by vexgen. They
// are validated here so that malformed data fails at load time.
func Expand(src Statement) ([]Statement, error) {
	if len(src.KernelVersionRanges) > 0 {
		if len(src.VersionRanges) > 0 {
			return nil, fmt.Errorf("versionRanges cannot be combined with kernelVersionRanges")
		}

		if src.From != "" || src.To != "" {
			return nil, fmt.Errorf("kernelVersionRanges cannot be combined with explicit from/to")
		}

		if err := validateKernelRanges(src.KernelVersionRanges); err != nil {
			return nil, err
		}

		return []Statement{src}, nil
	}

	if len(src.VersionRanges) == 0 {
		return []Statement{src}, nil
	}

	if src.From != "" || src.To != "" {
		return nil, fmt.Errorf("versionRanges cannot be combined with explicit from/to")
	}

	parsed := make([]parsedRange, 0, len(src.VersionRanges))

	for _, c := range src.VersionRanges {
		r, err := parseConstraint(c)
		if err != nil {
			return nil, err
		}

		parsed = append(parsed, r)
	}

	if err := checkOverlap(parsed); err != nil {
		return nil, err
	}

	out := make([]Statement, 0, len(parsed))

	for _, r := range parsed {
		stmt := src
		stmt.VersionRanges = nil
		stmt.From = r.from
		stmt.To = r.to
		out = append(out, stmt)
	}

	return out, nil
}

// validateKernelRanges parses every kernel range and rejects overlaps, so that
// bad data is caught at load time rather than silently mismatching later.
func validateKernelRanges(ranges []string) error {
	parsed := make([]parsedRange, 0, len(ranges))

	for _, c := range ranges {
		r, err := parseKernelConstraint(c)
		if err != nil {
			return err
		}

		parsed = append(parsed, r)
	}

	return checkKernelOverlap(parsed)
}

type parsedRange struct {
	raw  string
	from string // inclusive lower bound
	to   string // exclusive upper bound, "" = unbounded above
}

// constraintRE matches `>= vX.Y.Z` optionally followed by `< vA.B.C`.
//
//	Group 1: lower version (always present)
//	Group 2: upper version (empty if forward)
var constraintRE = regexp.MustCompile(
	`^\s*>=\s*(v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?)` +
		`(?:\s+<\s*(v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?))?\s*$`,
)

func parseConstraint(s string) (parsedRange, error) {
	m := constraintRE.FindStringSubmatch(s)
	if m == nil {
		return parsedRange{}, fmt.Errorf(
			"invalid versionRange %q (expected `>= vX.Y.Z` or `>= vX.Y.Z < vA.B.C`)", s,
		)
	}

	r := parsedRange{raw: s, from: m[1], to: m[2]}

	if r.to != "" && gitversion.CompareVersions(r.from, r.to) >= 0 {
		return parsedRange{}, fmt.Errorf("empty range in %q: lower bound is not strictly less than upper bound", s)
	}

	return r, nil
}

// kernelConstraintRE matches `>= X.Y.Z` optionally followed by `< A.B.C`.
// Kernel versions carry no "v" prefix. Talos always ships a fully qualified
// stable release, so only the three-component form is accepted.
//
//	Group 1: lower version (always present)
//	Group 2: upper version (empty if forward)
var kernelConstraintRE = regexp.MustCompile(
	`^\s*>=\s*(\d+\.\d+\.\d+)(?:\s+<\s*(\d+\.\d+\.\d+))?\s*$`,
)

// ParseKernelRange parses a single kernelVersionRanges entry and returns its
// inclusive lower bound and exclusive upper bound. An empty upper bound means
// unbounded above.
func ParseKernelRange(s string) (from, to string, err error) {
	r, err := parseKernelConstraint(s)
	if err != nil {
		return "", "", err
	}

	return r.from, r.to, nil
}

func parseKernelConstraint(s string) (parsedRange, error) {
	m := kernelConstraintRE.FindStringSubmatch(s)
	if m == nil {
		return parsedRange{}, fmt.Errorf(
			"invalid kernelVersionRange %q (expected `>= X.Y.Z` or `>= X.Y.Z < A.B.C`)", s,
		)
	}

	r := parsedRange{raw: s, from: m[1], to: m[2]}

	if r.to != "" {
		cmp, err := kernelversion.CompareVersions(r.from, r.to)
		if err != nil {
			return parsedRange{}, fmt.Errorf("invalid kernelVersionRange %q: %w", s, err)
		}

		if cmp >= 0 {
			return parsedRange{}, fmt.Errorf("empty range in %q: lower bound is not strictly less than upper bound", s)
		}
	}

	return r, nil
}

// checkKernelOverlap reports an error if any two half-open kernel ranges
// intersect. Treats an empty `to` as +∞.
func checkKernelOverlap(ranges []parsedRange) error {
	for i := range ranges {
		for j := i + 1; j < len(ranges); j++ {
			overlap, err := kernelRangesOverlap(ranges[i], ranges[j])
			if err != nil {
				return err
			}

			if overlap {
				return fmt.Errorf("overlapping kernelVersionRanges: %q and %q", ranges[i].raw, ranges[j].raw)
			}
		}
	}

	return nil
}

// kernelRangesOverlap: half-open [a.from, a.to) intersects [b.from, b.to) iff
// a.from < b.to AND b.from < a.to.
func kernelRangesOverlap(a, b parsedRange) (bool, error) {
	if a.to != "" {
		cmp, err := kernelversion.CompareVersions(b.from, a.to)
		if err != nil {
			return false, err
		}

		if cmp >= 0 {
			return false, nil
		}
	}

	if b.to != "" {
		cmp, err := kernelversion.CompareVersions(a.from, b.to)
		if err != nil {
			return false, err
		}

		if cmp >= 0 {
			return false, nil
		}
	}

	return true, nil
}

// checkOverlap reports an error if any two half-open ranges intersect.
// Treats an empty `to` as +∞.
func checkOverlap(ranges []parsedRange) error {
	for i := range ranges {
		for j := i + 1; j < len(ranges); j++ {
			if rangesOverlap(ranges[i], ranges[j]) {
				return fmt.Errorf("overlapping versionRanges: %q and %q", ranges[i].raw, ranges[j].raw)
			}
		}
	}

	return nil
}

// rangesOverlap: half-open [a.from, a.to) intersects [b.from, b.to) iff
// a.from < b.to AND b.from < a.to.
func rangesOverlap(a, b parsedRange) bool {
	if a.to != "" && gitversion.CompareVersions(b.from, a.to) >= 0 {
		return false
	}

	if b.to != "" && gitversion.CompareVersions(a.from, b.to) >= 0 {
		return false
	}

	return true
}

func statementError(i int, s Statement, err error) error {
	return fmt.Errorf("statement %d (%s): %w", i, s.Name, err)
}
