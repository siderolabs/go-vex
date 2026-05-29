// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

// Package gitversion provides functions to compare git describe versions, like
// "v1.0.0-35-g46d67fe44" and "v1.0.0-alpha.1-35-g46d67fe44"
// It can also compare pure semantic versions like "v1.0.0" and "v1.0.0-alpha.1".
package gitversion

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// GitRevRegex matches e.g. v1.0.0-35-g46d67fe44 -> [v1.0.0, 35]
// v1.0.0-alpha.1-35-g46d67fe44 -> [v1.0.0-alpha.1, 35].
var GitRevRegex = regexp.MustCompile(`^(v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?)(?:-(\d+)-g[0-9a-fA-F]+)?(?:-dirty)?$`)

// ValidateVersion validates versions.
// Valid versions are expected to be in the format:
// v1.0.0-35-g46d67fe44, v1.0.0-alpha.1, v1.0.0-rc.3,
// or plain semantic versions like v1.0.0, v2.3.4, etc.
func ValidateVersion(version string) bool {
	return len(GitRevRegex.FindStringSubmatch(version)) > 0
}

// StripGitSuffix removes the Git revision suffix from the provided version string.
// It uses the GitRevRegex to identify and strip any Git-specific suffixes,
// returning the cleaned version string.
func StripGitSuffix(version string) string {
	if !ValidateVersion(version) {
		return version
	}

	return GitRevRegex.FindStringSubmatch(version)[1]
}

// CompareVersions compares two version strings that may include semantic versioning and git commit counts.
// It first compares the semantic versions (after stripping any git suffix).
// If the semantic versions are equal, it compares the number of commits since the last tag using regex extraction.
// Returns an integer indicating the comparison result (-1 if a < b, 0 if a == b, 1 if a > b), or an error if parsing fails.
func CompareVersions(a, b string) int {
	matchesA := GitRevRegex.FindStringSubmatch(a)

	matchesB := GitRevRegex.FindStringSubmatch(b)

	if len(matchesA) == 0 || len(matchesB) == 0 {
		// Either version is not valid, best-effort string comparison
		return cmp.Compare(a, b)
	}

	// Index 0 is the full match, index 1 is the version without git suffix, index 2 is the commit count
	if result := semver.Compare(matchesA[1], matchesB[1]); result != 0 {
		return result
	}

	if matchesA[2] == "" && matchesB[2] != "" {
		// a has no git suffix, b has git suffix, so b is newer
		return -1
	}

	if matchesA[2] != "" && matchesB[2] == "" {
		// a has git suffix, b has no git suffix, so a is newer
		return 1
	}

	// If everything is equal, check for dirty suffix
	dirtyA := strings.HasSuffix(a, "-dirty")
	dirtyB := strings.HasSuffix(b, "-dirty")

	// Both have git suffixes, compare the commit counts
	commitsA, errA := strconv.Atoi(matchesA[2])

	commitsB, errB := strconv.Atoi(matchesB[2])
	if errA != nil || errB != nil {
		// If either commit count is not a valid integer, use dirty
		if dirtyA && !dirtyB {
			return 1
		}

		if !dirtyA && dirtyB {
			return -1
		}

		return cmp.Compare(a, b) // Fallback to string comparison
	}

	if result := cmp.Compare(commitsA, commitsB); result != 0 {
		return result
	}

	if dirtyA && !dirtyB {
		return 1
	}

	if !dirtyA && dirtyB {
		return -1
	}

	return 0
}

// VersionInRangeExclusive checks if version is in the half-open range
// [from, to): inclusive on the lower bound, exclusive on the upper.
// An empty "from" means unbounded below; an empty "to" means unbounded above.
func VersionInRangeExclusive(version, from, to string) (bool, error) {
	ok, err := VersionInRange(version, from, to)
	if err != nil || !ok {
		return ok, err
	}

	if to != "" && CompareVersions(version, to) == 0 {
		return false, nil
	}

	return true, nil
}

// VersionInRange checks if a given version is within the specified range [from, to], inclusive.
// It reports an error if the version format cannot be compared.
func VersionInRange(version, from, to string) (bool, error) {
	// Validate the version
	if !ValidateVersion(version) {
		return false, fmt.Errorf("invalid version format")
	}

	// If both 'from' and 'to' are present, validate range
	if from != "" && to != "" {
		if !ValidateVersion(from) || !ValidateVersion(to) {
			return false, fmt.Errorf("invalid from or to version format")
		}

		if CompareVersions(from, to) > 0 {
			return false, fmt.Errorf("'from' version cannot be greater than 'to' version")
		}
	}

	// Validate 'from' if provided
	if from != "" {
		if !ValidateVersion(from) {
			return false, fmt.Errorf("invalid from version format")
		}

		if CompareVersions(version, from) < 0 {
			return false, nil // version is before 'from'
		}
	}

	// Validate 'to' if provided
	if to != "" {
		if !ValidateVersion(to) {
			return false, fmt.Errorf("invalid to version format")
		}

		if CompareVersions(version, to) > 0 {
			return false, nil // version is after 'to'
		}
	}

	return true, nil // version is within the range
}
