// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1_test

import (
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-vex/pkg/types/v1alpha1"
)

func TestExpand_Passthrough(t *testing.T) {
	src := v1alpha1.Statement{
		Name:   "CVE-1",
		Status: vex.StatusFixed,
		From:   "v1.12.7",
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, src, got[0])
}

func TestExpand_ForwardSingle(t *testing.T) {
	src := v1alpha1.Statement{
		Name:          "CVE-1",
		Status:        vex.StatusFixed,
		StatusNotes:   "fixed in stable kernel",
		VersionRanges: []string{">= v1.12.9"},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 1)

	assert.Equal(t, vex.StatusFixed, got[0].Status)
	assert.Equal(t, "v1.12.9", got[0].From)
	assert.Empty(t, got[0].To, "bare `>=` should leave To unbounded")
	assert.Equal(t, "fixed in stable kernel", got[0].StatusNotes)
	assert.Empty(t, got[0].VersionRanges, "VersionRanges should be stripped on expanded statements")
}

func TestExpand_BoundedSingle(t *testing.T) {
	src := v1alpha1.Statement{
		Name:          "CVE-1",
		Status:        vex.StatusFixed,
		VersionRanges: []string{">= v1.12.7 < v1.13.0"},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 1)

	assert.Equal(t, "v1.12.7", got[0].From)
	assert.Equal(t, "v1.13.0", got[0].To)
}

func TestExpand_BoundedStoresLiterally(t *testing.T) {
	// `to` is stored as written; vexgen interprets it as exclusive.
	cases := map[string]struct {
		input string
		from  string
		to    string
	}{
		"patch boundary":   {">= v1.13.0 < v1.13.5", "v1.13.0", "v1.13.5"},
		"minor boundary":   {">= v1.12.7 < v1.13.0", "v1.12.7", "v1.13.0"},
		"pre at boundary":  {">= v1.13.0 < v1.14.0-alpha.0", "v1.13.0", "v1.14.0-alpha.0"},
		"major boundary":   {">= v1.99.0 < v2.0.0", "v1.99.0", "v2.0.0"},
		"both pre-release": {">= v1.14.0-alpha.0 < v1.14.0-alpha.5", "v1.14.0-alpha.0", "v1.14.0-alpha.5"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src := v1alpha1.Statement{
				Name:          "CVE-1",
				Status:        vex.StatusFixed,
				VersionRanges: []string{tc.input},
			}

			got, err := v1alpha1.Expand(src)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tc.from, got[0].From)
			assert.Equal(t, tc.to, got[0].To)
		})
	}
}

func TestExpand_MultiLineFix(t *testing.T) {
	src := v1alpha1.Statement{
		Name:   "CVE-1",
		Status: vex.StatusFixed,
		VersionRanges: []string{
			">= v1.12.8 < v1.13.0",
			">= v1.13.1 < v1.14.0-alpha.0",
			">= v1.14.0-alpha.0",
		},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 3)

	assert.Equal(t, "v1.12.8", got[0].From)
	assert.Equal(t, "v1.13.0", got[0].To)
	assert.Equal(t, "v1.13.1", got[1].From)
	assert.Equal(t, "v1.14.0-alpha.0", got[1].To)
	assert.Equal(t, "v1.14.0-alpha.0", got[2].From)
	assert.Empty(t, got[2].To, "trailing forward entry should be unbounded above")

	for _, s := range got {
		assert.Equal(t, vex.StatusFixed, s.Status)
	}
}

func TestExpand_NotAffectedStatus(t *testing.T) {
	src := v1alpha1.Statement{
		Name:          "CVE-1",
		Status:        vex.StatusNotAffected,
		Justification: vex.VulnerableCodeNotPresent,
		VersionRanges: []string{">= v1.13.0 < v1.14.0-alpha.0"},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 1)

	assert.Equal(t, vex.StatusNotAffected, got[0].Status)
	assert.Equal(t, vex.VulnerableCodeNotPresent, got[0].Justification)
	assert.Equal(t, "v1.13.0", got[0].From)
	assert.Equal(t, "v1.14.0-alpha.0", got[0].To)
}

func TestExpand_RejectsCombiningWithFromTo(t *testing.T) {
	src := v1alpha1.Statement{
		Name:          "CVE-1",
		Status:        vex.StatusFixed,
		From:          "v1.12.0",
		VersionRanges: []string{">= v1.12.9"},
	}

	_, err := v1alpha1.Expand(src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "from/to")
}

func TestExpand_RejectsOverlap(t *testing.T) {
	cases := map[string][]string{
		"forward overlaps forward":    {">= v1.12.7", ">= v1.13.0"},
		"bounded overlaps bounded":    {">= v1.12.7 < v1.13.0", ">= v1.12.8 < v1.13.0"},
		"forward swallows bounded":    {">= v1.12.0", ">= v1.13.1 < v1.14.0-alpha.0"},
		"two forwards":                {">= v1.12.0", ">= v1.99.0"},
		"adjacent inclusive boundary": {">= v1.12.7 < v1.13.1", ">= v1.13.0 < v1.14.0-alpha.0"},
	}

	for name, ranges := range cases {
		t.Run(name, func(t *testing.T) {
			src := v1alpha1.Statement{
				Name:          "CVE-1",
				Status:        vex.StatusFixed,
				VersionRanges: ranges,
			}

			_, err := v1alpha1.Expand(src)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "overlap")
		})
	}
}

func TestExpand_AcceptsAdjacentRanges(t *testing.T) {
	// Half-open semantics: upper bound of one range can equal the lower
	// bound of the next without overlap.
	src := v1alpha1.Statement{
		Name:   "CVE-1",
		Status: vex.StatusFixed,
		VersionRanges: []string{
			">= v1.12.7 < v1.13.0",
			">= v1.13.0 < v1.14.0-alpha.0",
			">= v1.14.0-alpha.0",
		},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	assert.Len(t, got, 3)
}

func TestExpand_RejectsMalformedConstraint(t *testing.T) {
	cases := map[string]string{
		"wrong operator":         ">v1.12.0",
		"unsupported operator":   "== v1.12.0",
		"missing v prefix":       ">= 1.12.0",
		"missing patch":          ">= v1.12",
		"too many components":    ">= v1.12.0.0",
		"unsupported prerelease": ">= v1.14.0-foo",
		"git suffix":             ">= v1.12.7-1-gdeadbeef",
		"pipe alternation":       ">= v1.12.7 || >= v1.13.0",
		"upper without lower":    "< v1.13.0",
		"backwards bounds":       ">= v1.13.5 < v1.13.0",
		"equal bounds":           ">= v1.13.5 < v1.13.5",
		"empty after operator":   ">= ",
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			src := v1alpha1.Statement{
				Name:          "CVE-1",
				Status:        vex.StatusFixed,
				VersionRanges: []string{c},
			}

			_, err := v1alpha1.Expand(src)
			require.Error(t, err)
		})
	}
}

func TestExpand_KernelRangesNotExpanded(t *testing.T) {
	src := v1alpha1.Statement{
		Name:   "CVE-2026-53078",
		Status: vex.StatusFixed,
		KernelVersionRanges: []string{
			">= 6.18.42 < 6.19.0",
			">= 7.0.10",
		},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)

	// Kernel ranges describe one version axis, not distinct release lines, so
	// the statement is carried through whole rather than split.
	require.Len(t, got, 1)
	assert.Equal(t, src, got[0])
}

func TestExpand_KernelRangesValidated(t *testing.T) {
	for _, test := range []struct {
		name    string
		errWant string
		src     v1alpha1.Statement
	}{
		{
			name: "malformed bound",
			src: v1alpha1.Statement{
				Name:                "CVE-1",
				KernelVersionRanges: []string{">= 6.18"},
			},
			errWant: "invalid kernelVersionRange",
		},
		{
			name: "v prefix is not a kernel version",
			src: v1alpha1.Statement{
				Name:                "CVE-1",
				KernelVersionRanges: []string{">= v6.18.42"},
			},
			errWant: "invalid kernelVersionRange",
		},
		{
			name: "empty range",
			src: v1alpha1.Statement{
				Name:                "CVE-1",
				KernelVersionRanges: []string{">= 6.19.0 < 6.18.0"},
			},
			errWant: "empty range",
		},
		{
			name: "overlapping ranges",
			src: v1alpha1.Statement{
				Name:                "CVE-1",
				KernelVersionRanges: []string{">= 6.18.42 < 6.19.0", ">= 6.18.44"},
			},
			errWant: "overlapping kernelVersionRanges",
		},
		{
			name: "cannot combine with versionRanges",
			src: v1alpha1.Statement{
				Name:                "CVE-1",
				VersionRanges:       []string{">= v1.13.8"},
				KernelVersionRanges: []string{">= 6.18.42"},
			},
			errWant: "cannot be combined with kernelVersionRanges",
		},
		{
			name: "cannot combine with from/to",
			src: v1alpha1.Statement{
				Name:                "CVE-1",
				From:                "v1.13.8",
				KernelVersionRanges: []string{">= 6.18.42"},
			},
			errWant: "cannot be combined with explicit from/to",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := v1alpha1.Expand(test.src)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errWant)
		})
	}
}

func TestParseKernelRange(t *testing.T) {
	for _, test := range []struct {
		input    string
		wantFrom string
		wantTo   string
	}{
		{input: ">= 6.18.42 < 6.19.0", wantFrom: "6.18.42", wantTo: "6.19.0"},
		{input: ">= 7.0.10", wantFrom: "7.0.10", wantTo: ""},
		{input: "  >=  6.18.42   <  6.19.0  ", wantFrom: "6.18.42", wantTo: "6.19.0"},
	} {
		t.Run(test.input, func(t *testing.T) {
			from, to, err := v1alpha1.ParseKernelRange(test.input)
			require.NoError(t, err)
			assert.Equal(t, test.wantFrom, from)
			assert.Equal(t, test.wantTo, to)
		})
	}
}
