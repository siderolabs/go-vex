// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-vex/pkg/types/v1alpha1"
)

// document renders a minimal VEX document with the given `created` scalar as
// written, so tests control whether YAML sees a quoted or a plain scalar.
func document(created string) string {
	return `author: Sidero Labs
ids:
  purl: pkg:generic/talos
statements:
  - name: CVE-2025-26519
    description: test
    created: ` + created + `
    from: v1.0.0
    to: v2.0.0
    status: not_affected
    justification: vulnerable_code_not_present
`
}

// TestLoadExploitabilityDataTimestamps asserts both YAML spellings of a
// timestamp load.
//
// A plain RFC3339 scalar resolves to !!timestamp and a quoted one to !!str, and
// go.yaml.in/yaml/v4 will not construct !!timestamp into a string field - so
// typing these fields as string silently accepts only quoted input and rejects
// every real document, which is how published VEX data stopped loading.
func TestLoadExploitabilityDataTimestamps(t *testing.T) {
	t.Parallel()

	expected := time.Date(2025, 7, 16, 13, 46, 22, 0, time.UTC)

	for _, test := range []struct {
		name    string
		created string
	}{
		{name: "plain", created: "2025-07-16T13:46:22Z"},
		{name: "quoted", created: `"2025-07-16T13:46:22Z"`},
		{name: "single quoted", created: `'2025-07-16T13:46:22Z'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			data, err := v1alpha1.LoadExploitabilityData(strings.NewReader(document(test.created)))
			require.NoError(t, err)

			require.Len(t, data.Statements, 1)
			assert.True(t, data.Statements[0].Created.Equal(expected),
				"want %s, got %s", expected, data.Statements[0].Created)

			// unset optional timestamps stay zero so vexgen can omit them.
			assert.True(t, data.Statements[0].ActionTime.IsZero())
			assert.True(t, data.Statements[0].LastUpdated.IsZero())
		})
	}
}

// TestLoadExploitabilityDataInvalidTimestamp asserts an unparseable timestamp is
// rejected at load, which is where vexgen used to catch it.
func TestLoadExploitabilityDataInvalidTimestamp(t *testing.T) {
	t.Parallel()

	_, err := v1alpha1.LoadExploitabilityData(strings.NewReader(document("not-a-timestamp")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error unmarshalling data")
}
