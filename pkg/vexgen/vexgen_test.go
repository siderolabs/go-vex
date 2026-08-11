// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package vexgen_test

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"

	"github.com/siderolabs/go-vex/pkg/types/v1alpha1"
	"github.com/siderolabs/go-vex/pkg/vexgen"
)

// ts parses an RFC3339 timestamp for use in test fixtures.
func ts(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic("parsing test timestamp " + value + ": " + err.Error())
	}

	return parsed
}

func TestMakeVersionedProductIDs(t *testing.T) {
	tests := []struct {
		ids            map[vex.IdentifierType]string
		expected       map[vex.IdentifierType]string
		name           string
		productVersion string
	}{
		{
			name: "PURL identifier",
			ids: map[vex.IdentifierType]string{
				vex.PURL: "pkg:generic/talos",
			},
			productVersion: "v1.0.0",
			expected: map[vex.IdentifierType]string{
				vex.PURL: "pkg:generic/talos@v1.0.0",
			},
		},
		{
			name: "CPE22 identifier",
			ids: map[vex.IdentifierType]string{
				vex.CPE22: "cpe:/o:siderolabs:talos",
			},
			productVersion: "v1.0.0",
			expected: map[vex.IdentifierType]string{
				vex.CPE22: "cpe:/o:siderolabs:talos:v1.0.0:*:*:*:*:*:*:*",
			},
		},
		{
			name: "CPE23 identifier",
			ids: map[vex.IdentifierType]string{
				vex.CPE23: "cpe:2.3:o:siderolabs:talos",
			},
			productVersion: "v1.0.0",
			expected: map[vex.IdentifierType]string{
				vex.CPE23: "cpe:2.3:o:siderolabs:talos:v1.0.0:*:*:*:*:*:*:*",
			},
		},
		{
			name: "multiple identifiers",
			ids: map[vex.IdentifierType]string{
				vex.PURL:  "pkg:generic/talos",
				vex.CPE22: "cpe:/o:siderolabs:talos",
				vex.CPE23: "cpe:2.3:o:siderolabs:talos",
			},
			productVersion: "v1.2.3",
			expected: map[vex.IdentifierType]string{
				vex.PURL:  "pkg:generic/talos@v1.2.3",
				vex.CPE22: "cpe:/o:siderolabs:talos:v1.2.3:*:*:*:*:*:*:*",
				vex.CPE23: "cpe:2.3:o:siderolabs:talos:v1.2.3:*:*:*:*:*:*:*",
			},
		},
		{
			name:           "empty input",
			ids:            map[vex.IdentifierType]string{},
			productVersion: "v1.0.0",
			expected:       map[vex.IdentifierType]string{},
		},
		{
			name: "unsupported identifier type",
			ids: map[vex.IdentifierType]string{
				"unknown": "some-value",
			},
			productVersion: "v1.0.0",
			expected:       map[vex.IdentifierType]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vexgen.MakeVersionedProductIDs(tt.ids, tt.productVersion)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertStatements(t *testing.T) {
	productIDs := map[vex.IdentifierType]string{
		vex.PURL: "pkg:generic/talos@v1.0.0",
	}

	tests := []struct {
		productIDs     map[vex.IdentifierType]string
		name           string
		productVersion string
		errorContains  string
		statements     []v1alpha1.Statement
		expectedCount  int
		expectError    bool
	}{
		{
			name: "valid statement in range",
			statements: []v1alpha1.Statement{
				{
					Name:          "CVE-2023-1234",
					Description:   "Test vulnerability",
					Created:       ts("2023-01-01T00:00:00Z"),
					From:          "v1.0.0",
					To:            "v2.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  1,
			expectError:    false,
		},
		{
			name: "statement out of range",
			statements: []v1alpha1.Statement{
				{
					Name:          "CVE-2023-1234",
					Description:   "Test vulnerability",
					Created:       ts("2023-01-01T00:00:00Z"),
					From:          "v2.0.0",
					To:            "v3.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  0,
			expectError:    false,
		},
		{
			name: "statement with all optional times",
			statements: []v1alpha1.Statement{
				{
					Name:          "CVE-2023-1234",
					Description:   "Test vulnerability",
					Created:       ts("2023-01-01T00:00:00Z"),
					ActionTime:    ts("2023-01-02T00:00:00Z"),
					LastUpdated:   ts("2023-01-03T00:00:00Z"),
					From:          "v1.0.0",
					To:            "v2.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
					Aliases:       []vex.VulnerabilityID{"ALIAS-1234"},
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  1,
			expectError:    false,
		},
		{
			name:           "empty statements",
			statements:     []v1alpha1.Statement{},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  0,
			expectError:    false,
		},
		{
			name: "multiple statements mixed",
			statements: []v1alpha1.Statement{
				{
					Name:          "CVE-2023-1234",
					Description:   "Test vulnerability 1",
					Created:       ts("2023-01-01T00:00:00Z"),
					From:          "v1.0.0",
					To:            "v2.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
				},
				{
					Name:          "CVE-2023-5678",
					Description:   "Test vulnerability 2",
					Created:       ts("2023-01-01T00:00:00Z"),
					From:          "v2.0.0",
					To:            "v3.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
				},
				{
					Name:          "CVE-2023-9999",
					Description:   "Test vulnerability 3",
					Created:       ts("2023-01-01T00:00:00Z"),
					From:          "v1.0.0",
					To:            "v3.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  2,
			expectError:    false,
		},
		{
			name: "statement missing justification for not_affected status",
			statements: []v1alpha1.Statement{
				{
					Name:        "CVE-2023-1234",
					Description: "Test vulnerability",
					Created:     ts("2023-01-01T00:00:00Z"),
					From:        "v1.0.0",
					To:          "v2.0.0",
					Status:      vex.StatusNotAffected,
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  0,
			expectError:    true,
			errorContains:  "either justification or impact statement must be defined",
		},
		{
			// a zero timestamp must not reach the document: the parse that used to
			// reject an empty created date is gone now that the field is typed.
			name: "statement missing created date",
			statements: []v1alpha1.Statement{
				{
					Name:          "CVE-2023-1234",
					Description:   "Test vulnerability",
					From:          "v1.0.0",
					To:            "v2.0.0",
					Status:        vex.StatusNotAffected,
					Justification: vex.VulnerableCodeNotPresent,
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  0,
			expectError:    true,
			errorContains:  "created date is required",
		},
		{
			name: "statement missing action for affected status",
			statements: []v1alpha1.Statement{
				{
					Name:        "CVE-2023-1234",
					Description: "Test vulnerability",
					Created:     ts("2023-01-01T00:00:00Z"),
					From:        "v1.0.0",
					To:          "v2.0.0",
					Status:      vex.StatusAffected,
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  0,
			expectError:    true,
			errorContains:  "action statement must be set when using status \"affected\"",
		},
		{
			name: "affected must not have impact",
			statements: []v1alpha1.Statement{
				{
					Name:        "CVE-2023-1234",
					Description: "Test vulnerability",
					Created:     ts("2023-01-01T00:00:00Z"),
					From:        "v1.0.0",
					To:          "v2.0.0",
					Status:      vex.StatusAffected,
					Impact:      "Allows remote code execution by an attacker with privileged pod access.",
				},
			},
			productIDs:     productIDs,
			productVersion: "v1.5.0",
			expectedCount:  0,
			expectError:    true,
			errorContains:  "impact statement should not be set when using status \"affected\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vexgen.ConvertStatements(tt.statements, tt.productIDs, tt.productVersion)

			if tt.expectError {
				if assert.Error(t, err) && tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, tt.expectedCount)

				if tt.expectedCount == len(tt.statements) {
					for i, stmt := range result {
						assert.Equal(t, tt.statements[i].Name, stmt.Vulnerability.Name)
						assert.Equal(t, tt.statements[i].Description, stmt.Vulnerability.Description)
						assert.Equal(t, tt.productIDs, stmt.Products[0].Identifiers)
						assert.NotNil(t, stmt.Timestamp)
					}
				}
			}
		})
	}
}

func TestE2E(t *testing.T) {
	for _, spec := range []struct {
		name        string
		version     string
		expectError string
		expectFile  string
		data        v1alpha1.ExploitabilityData
	}{
		{
			name: "invalid record",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs: map[vex.IdentifierType]string{
					vex.PURL:  "pkg:generic/talos@v1.0.0",
					vex.CPE22: "cpe:/o:siderolabs:talos:v1.0.0:*:*:*:*:*:*:*",
					vex.CPE23: "cpe:2.3:o:siderolabs:talos:v1.0.0:*:*:*:*:*:*:*",
				},
				Statements: []v1alpha1.Statement{
					{
						Name:          "CVE-2023-1234",
						Description:   "Test vulnerability",
						Created:       ts("2023-01-01T00:00:00Z"),
						From:          "v1.0.0",
						To:            "v2.0.0",
						Status:        vex.StatusAffected,
						Justification: vex.ComponentNotPresent,
					},
				},
			},
			version:     "v1.0.0",
			expectError: "justification should not be set when using status \"affected\"",
			expectFile:  "./testdata/empty.json",
		},
		{
			name: "valid record, but version not in range",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs:    map[vex.IdentifierType]string{},
				Statements: []v1alpha1.Statement{
					{
						Name:        "CVE-2023-1234",
						Description: "Test vulnerability",
						Created:     ts("2023-01-01T00:00:00Z"),
						From:        "v1.5.0",
						To:          "v2.0.0",
						Status:      vex.StatusAffected,
						Impact:      "Allows remote code execution by an attacker with privileged pod access.",
					},
				},
			},
			version:    "v1.0.0",
			expectFile: "./testdata/empty.json",
		},
		{
			name: "multiple valid statements, only one applies",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs: map[vex.IdentifierType]string{
					vex.PURL: "pkg:generic/talos",
				},
				Statements: []v1alpha1.Statement{
					{
						Name:        "CVE-2025-26519",
						Description: "Musl versions before 1.2.6 are vulnerable to invalid input",
						Created:     ts("2025-07-14T12:00:00Z"),
						From:        "v1.10.0-alpha.1-35-g46d67fe44",
						Status:      vex.StatusFixed,
						StatusNotes: "https://github.com/siderolabs/toolchain/commit/818b320288afa40da07f95998b8739bf211a9f9c",
					},
					{
						Name:          "CVE-2025-40014",
						Created:       ts("2025-07-14T14:00:00Z"),
						From:          "v1.4.0-alpha.0-16-g683b4ccb4",
						Status:        vex.StatusNotAffected,
						Justification: vex.VulnerableCodeNotPresent,
						StatusNotes:   "Talos kernel configurations do not enable the affected driver in any build",
					},
				},
			},
			version:    "v1.10.0-alpha.1",
			expectFile: "./testdata/40014.json",
		},
		{
			name: "multiple valid statements, none apply",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs: map[vex.IdentifierType]string{
					vex.PURL: "pkg:generic/talos",
				},
				Statements: []v1alpha1.Statement{
					{
						Name:        "CVE-2025-26519",
						Description: "Musl versions before 1.2.6 are vulnerable to invalid input",
						Created:     ts("2025-07-14T12:00:00Z"),
						From:        "v1.10.0-alpha.1-35-g46d67fe44",
						Status:      vex.StatusFixed,
						StatusNotes: "https://github.com/siderolabs/toolchain/commit/818b320288afa40da07f95998b8739bf211a9f9c",
					},
					{
						Name:          "CVE-2025-40014",
						Created:       ts("2025-07-14T14:00:00Z"),
						From:          "v1.4.0-alpha.0-16-g683b4ccb4",
						Status:        vex.StatusNotAffected,
						Justification: vex.VulnerableCodeNotPresent,
						StatusNotes:   "Talos kernel configurations do not enable the affected driver in any build",
					},
				},
			},
			version:    "v1.1.1",
			expectFile: "./testdata/empty.json",
		},
		{
			name: "multiple valid statements, both apply",
			data: v1alpha1.ExploitabilityData{
				Author: "Test Author",
				IDs: map[vex.IdentifierType]string{
					vex.PURL: "pkg:generic/talos",
				},
				Statements: []v1alpha1.Statement{
					{
						Name:        "CVE-2025-26519",
						Description: "Musl versions before 1.2.6 are vulnerable to invalid input",
						Created:     ts("2025-07-14T12:00:00Z"),
						From:        "v1.10.0-alpha.1-35-g46d67fe44",
						Status:      vex.StatusFixed,
						StatusNotes: "https://github.com/siderolabs/toolchain/commit/818b320288afa40da07f95998b8739bf211a9f9c",
					},
					{
						Name:          "CVE-2025-40014",
						Created:       ts("2025-07-14T14:00:00Z"),
						From:          "v1.4.0-alpha.0-16-g683b4ccb4",
						Status:        vex.StatusNotAffected,
						Justification: vex.VulnerableCodeNotPresent,
						StatusNotes:   "Talos kernel configurations do not enable the affected driver in any build",
					},
				},
			},
			version:    "v1.11.0-alpha.1",
			expectFile: "./testdata/two.json",
		},
	} {
		t.Run(spec.name, func(t *testing.T) {
			timestamp, err := time.Parse(time.RFC3339, "2025-07-16T13:46:22Z")
			assert.NoError(t, err)

			doc, err := vexgen.Populate(&spec.data, spec.version, &timestamp, "go-vex-test")
			if spec.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), spec.expectError)
			} else {
				assert.NoError(t, err)
			}

			assert.NotNil(t, doc)

			buf := bytes.NewBufferString("")
			err = vexgen.Serialize(doc, buf)
			assert.NoError(t, err)
			assert.NotEmpty(t, buf.String())

			if spec.expectFile != "" {
				f, err := os.Open(spec.expectFile)
				assert.NoError(t, err)

				defer f.Close() //nolint:errcheck

				contents, err := io.ReadAll(f)
				assert.NoError(t, err)

				assert.Equal(t, string(contents), buf.String())
			}
		})
	}
}
