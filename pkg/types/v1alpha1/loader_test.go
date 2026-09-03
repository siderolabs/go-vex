// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-vex/pkg/types/v1alpha1"
)

func TestLoadExploitabilityDataRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := v1alpha1.LoadExploitabilityData(strings.NewReader(`
author: test
statements:
  - name: CVE-TEST
    status: fixed
    created: "2026-01-01T00:00:00Z"
    kernelVersionRange:
      - ">= 6.18.42 < 6.19.0"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "field kernelVersionRange not found")
}

func TestLoadExploitabilityDataAcceptsKernelVersionRanges(t *testing.T) {
	t.Parallel()

	data, err := v1alpha1.LoadExploitabilityData(strings.NewReader(`
author: test
statements:
  - name: CVE-TEST
    status: fixed
    created: "2026-01-01T00:00:00Z"
    kernelVersionRanges:
      - ">= 6.18.42 < 6.19.0"
`))
	require.NoError(t, err)
	require.Len(t, data.Statements, 1)
	assert.Equal(t, []string{">= 6.18.42 < 6.19.0"}, data.Statements[0].KernelVersionRanges)
}
