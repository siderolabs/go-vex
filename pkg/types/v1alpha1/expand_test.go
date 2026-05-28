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

func TestExpand_SingleConstraint(t *testing.T) {
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
	assert.Equal(t, "v1.12.999", got[0].To)
	assert.Equal(t, "fixed in stable kernel", got[0].StatusNotes)
	assert.Empty(t, got[0].VersionRanges, "VersionRanges should be stripped on expanded statements")
}

func TestExpand_MultiLineFix(t *testing.T) {
	src := v1alpha1.Statement{
		Name:   "CVE-1",
		Status: vex.StatusFixed,
		VersionRanges: []string{
			">= v1.13.1",
			">= v1.12.8",
			">= v1.14.0-alpha.0",
		},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 3)

	// Order is the input order (not sorted).
	assert.Equal(t, "v1.13.1", got[0].From)
	assert.Equal(t, "v1.13.999", got[0].To)
	assert.Equal(t, "v1.12.8", got[1].From)
	assert.Equal(t, "v1.12.999", got[1].To)
	assert.Equal(t, "v1.14.0-alpha.0", got[2].From)
	assert.Equal(t, "v1.14.999", got[2].To)

	for _, s := range got {
		assert.Equal(t, vex.StatusFixed, s.Status)
	}
}

func TestExpand_NotAffectedStatus(t *testing.T) {
	src := v1alpha1.Statement{
		Name:          "CVE-1",
		Status:        vex.StatusNotAffected,
		Justification: vex.VulnerableCodeNotPresent,
		VersionRanges: []string{">= v1.13.0"},
	}

	got, err := v1alpha1.Expand(src)
	require.NoError(t, err)
	require.Len(t, got, 1)

	assert.Equal(t, vex.StatusNotAffected, got[0].Status)
	assert.Equal(t, vex.VulnerableCodeNotPresent, got[0].Justification)
	assert.Equal(t, "v1.13.0", got[0].From)
	assert.Equal(t, "v1.13.999", got[0].To)
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

func TestExpand_RejectsDuplicateLine(t *testing.T) {
	src := v1alpha1.Statement{
		Name:   "CVE-1",
		Status: vex.StatusFixed,
		VersionRanges: []string{
			">= v1.12.8",
			">= v1.12.9",
		},
	}

	_, err := v1alpha1.Expand(src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
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
