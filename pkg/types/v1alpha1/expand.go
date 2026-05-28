// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1

import (
	"fmt"
	"regexp"
	"strconv"
)

// Expand converts a Statement into one or more Statement values.
//
// When VersionRanges is empty, the statement passes through unchanged.
//
// When VersionRanges is non-empty, each ">= vX.Y.Z" constraint expands into
// exactly one Statement bounded to the X.Y release line:
//
//	from = vX.Y.Z              (the anchor as written)
//	to   = vX.Y.999             (per-line sentinel — talos versions are always
//	                             3-component and never reach .999)
//
// The expanded statement inherits the source's Status and every other field
// (Action, Justification, StatusNotes, Created, ...). Lines not listed are
// silent — downstream consumers treat "no statement" as vulnerable.
//
// VersionRanges cannot be combined with explicit From/To. Two constraints
// cannot target the same X.Y line.
func Expand(src Statement) ([]Statement, error) {
	if len(src.VersionRanges) == 0 {
		return []Statement{src}, nil
	}

	if src.From != "" || src.To != "" {
		return nil, fmt.Errorf("versionRanges cannot be combined with explicit from/to")
	}

	out := make([]Statement, 0, len(src.VersionRanges))
	seenLines := map[string]string{}

	for _, c := range src.VersionRanges {
		a, err := parseConstraint(c)
		if err != nil {
			return nil, err
		}

		lineKey := fmt.Sprintf("%d.%d", a.major, a.minor)
		if prev, dup := seenLines[lineKey]; dup {
			return nil, fmt.Errorf("duplicate constraint on %s line: %q and %q", lineKey, prev, c)
		}

		seenLines[lineKey] = c

		stmt := src
		stmt.VersionRanges = nil
		stmt.From = a.version
		stmt.To = fmt.Sprintf("v%d.%d.999", a.major, a.minor)
		out = append(out, stmt)
	}

	return out, nil
}

type parsedAnchor struct {
	version string
	major   int
	minor   int
}

// constraintRE matches `>= vX.Y.Z` or `>= vX.Y.Z-(alpha|beta|rc).N`.
// Captures: full version string, major, minor.
var constraintRE = regexp.MustCompile(`^\s*>=\s*(v(\d+)\.(\d+)\.\d+(?:-(?:alpha|beta|rc)\.\d+)?)\s*$`)

func parseConstraint(s string) (parsedAnchor, error) {
	m := constraintRE.FindStringSubmatch(s)
	if m == nil {
		return parsedAnchor{}, fmt.Errorf("invalid versionRange %q (expected `>= vX.Y.Z` or `>= vX.Y.Z-(alpha|beta|rc).N`)", s)
	}

	major, err := strconv.Atoi(m[2])
	if err != nil {
		return parsedAnchor{}, fmt.Errorf("invalid major in %q: %w", s, err)
	}

	minor, err := strconv.Atoi(m[3])
	if err != nil {
		return parsedAnchor{}, fmt.Errorf("invalid minor in %q: %w", s, err)
	}

	return parsedAnchor{version: m[1], major: major, minor: minor}, nil
}

func statementError(i int, s Statement, err error) error {
	return fmt.Errorf("statement %d (%s): %w", i, s.Name, err)
}
