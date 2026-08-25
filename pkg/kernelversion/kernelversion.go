// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

// Package kernelversion compares Linux kernel versions of the form X.Y.Z.
//
// It plays the same role for kernel versions that the gitversion package plays
// for Talos versions: parsing, ordering, and half-open range checks. It is kept
// deliberately narrow. Talos always ships a fully qualified stable kernel
// release, so only the X.Y.Z form is accepted; mainline shorthand ("6.18"),
// release candidates ("7.1-rc1") and the four-component legacy forms that
// appear in kernel CVE records are rejected rather than guessed at.
package kernelversion

import (
	"fmt"
	"regexp"
	"strconv"
)

// Version is a parsed X.Y.Z kernel version.
type Version struct {
	Major int
	Minor int
	Patch int
}

// versionRE matches a bare X.Y.Z kernel version, with no "v" prefix and no
// pre-release or metadata suffix.
var versionRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// Validate reports whether s is a well-formed X.Y.Z kernel version.
func Validate(s string) bool {
	return versionRE.MatchString(s)
}

// Parse parses a kernel version of the form X.Y.Z.
func Parse(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("invalid kernel version %q (expected X.Y.Z)", s)
	}

	// Each group is \d+ so the conversions cannot fail on anything the regexp
	// accepted, other than an out-of-range value.
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid kernel version %q: %w", s, err)
	}

	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return Version{}, fmt.Errorf("invalid kernel version %q: %w", s, err)
	}

	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return Version{}, fmt.Errorf("invalid kernel version %q: %w", s, err)
	}

	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// String renders the version back to its canonical dotted form.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Branch returns the major.minor stable branch identifier, e.g. "6.18".
//
// Kernel fixes are backported per stable branch, so a fix present in 6.18.42
// says nothing about 6.19.x. Callers bound ranges by branch to express that.
func (v Version) Branch() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Compare returns -1 if v sorts before other, 0 if they are equal, and 1 if v
// sorts after other.
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		return cmpInt(v.Major, other.Major)
	}

	if v.Minor != other.Minor {
		return cmpInt(v.Minor, other.Minor)
	}

	return cmpInt(v.Patch, other.Patch)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// CompareVersions compares two kernel version strings. It returns an error if
// either side is not a valid X.Y.Z version.
func CompareVersions(a, b string) (int, error) {
	va, err := Parse(a)
	if err != nil {
		return 0, err
	}

	vb, err := Parse(b)
	if err != nil {
		return 0, err
	}

	return va.Compare(vb), nil
}

// VersionInRangeExclusive reports whether version lies in the half-open range
// [from, to): inclusive on the lower bound, exclusive on the upper.
//
// An empty "from" means unbounded below; an empty "to" means unbounded above.
func VersionInRangeExclusive(version, from, to string) (bool, error) {
	v, err := Parse(version)
	if err != nil {
		return false, err
	}

	if from != "" {
		f, err := Parse(from)
		if err != nil {
			return false, fmt.Errorf("invalid lower bound: %w", err)
		}

		if to != "" {
			t, err := Parse(to)
			if err != nil {
				return false, fmt.Errorf("invalid upper bound: %w", err)
			}

			if f.Compare(t) >= 0 {
				return false, fmt.Errorf("empty range: lower bound %q is not strictly less than upper bound %q", from, to)
			}
		}

		if v.Compare(f) < 0 {
			return false, nil
		}
	}

	if to != "" {
		t, err := Parse(to)
		if err != nil {
			return false, fmt.Errorf("invalid upper bound: %w", err)
		}

		if v.Compare(t) >= 0 {
			return false, nil
		}
	}

	return true, nil
}
