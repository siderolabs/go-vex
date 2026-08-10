// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

//go:build !race

package scanner_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-vex/pkg/scanner"
)

var testDocument = models.Document{
	Matches: []models.Match{
		{
			Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{
					ID: "CVE-1234-5678",
				},
			},
		},
	},
}

func assertFileEqual(t *testing.T, expectedFile, actualFile string) {
	const recordResults = false

	actual, err := os.ReadFile(actualFile)
	assert.NoError(t, err)

	expected, err := os.ReadFile(expectedFile)
	assert.NoError(t, err)

	if recordResults && !bytes.Equal(expected, actual) {
		t.Log("failing the test in record mode")
		t.Fail()

		require.NoError(t, os.WriteFile(expectedFile, actual, 0o644))
	}

	assert.Equal(t, string(expected), string(actual))
}

func TestFormatReport(t *testing.T) {
	dir := t.TempDir()

	reportFile := filepath.Join(dir, "report.json")
	err := scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, scanner.ReportFormatJSON)
	assert.NoError(t, err)

	assertFileEqual(t, "./testdata/report.json", reportFile)

	reportFile = filepath.Join(dir, "report.table")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, scanner.ReportFormatTable)
	assert.NoError(t, err)

	assertFileEqual(t, "./testdata/report.table", reportFile)

	reportFile = filepath.Join(dir, "report.sarif")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, scanner.ReportFormatSARIF)
	assert.NoError(t, err)

	assertFileEqual(t, "./testdata/report.sarif", reportFile)

	reportFile = filepath.Join(dir, "report.cdx")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, scanner.ReportFormatCDX)
	assert.NoError(t, err)

	actual, err := os.ReadFile(reportFile)
	assert.NoError(t, err)

	expected, err := os.ReadFile("./testdata/report.cdx")
	assert.NoError(t, err)

	// Only test the deterministic part
	assert.Contains(t, string(actual), string(expected))

	reportFile = filepath.Join(dir, "report.unk")
	err = scanner.FormatReport(testDocument, reportFile, &sbom.SBOM{}, scanner.ReportFormat(-1))
	assert.ErrorContains(t, err, "unknown format: unk")

	_, err = os.ReadFile(reportFile)
	assert.ErrorContains(t, err, "no such file or directory")
}

func TestNewScanner(t *testing.T) {
	sc, err := scanner.NewScanner(scanner.Options{
		ID: "test",
	})
	assert.NoError(t, err)
	assert.NotNil(t, sc)

	assert.NoError(t, sc.Close())
}

func TestScanSBOM(t *testing.T) {
	timestamp, err := time.Parse(time.RFC3339, "2025-07-16T13:46:22Z")
	assert.NoError(t, err)

	sc, err := scanner.NewScanner(scanner.Options{
		ID: "test",
	})
	assert.NoError(t, err)
	assert.NotNil(t, sc)

	doc, sbom, err := sc.ScanSBOM("./testdata/test.spdx.json", &timestamp, "./testdata/26519.json")
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.NotNil(t, sbom)
	assert.Equal(t, 2, sbom.Artifacts.Packages.PackageCount()) // two packages left for test

	assert.Equal(t, "2025-07-16T13:46:22Z", doc.Descriptor.Timestamp)

	// the report has to name the DB build it came from: two reports that disagree
	// are otherwise indistinguishable.
	dbStatus, ok := doc.Descriptor.DB.(scanner.DatabaseStatus)
	require.True(t, ok, "expected descriptor.db to hold a DatabaseStatus, got %T", doc.Descriptor.DB)
	require.NotNil(t, dbStatus.Status)
	assert.False(t, dbStatus.Status.Built.IsZero(), "expected a DB build timestamp")
	assert.NotEmpty(t, dbStatus.Status.SchemaVersion)
	assert.Empty(t, dbStatus.Status.Path, "expected the local DB path to be left out of reports")
	assert.NotEmpty(t, dbStatus.Providers)

	matchesWithVex := len(doc.Matches)
	found26519 := false
	found67499 := false

	for _, m := range doc.Matches {
		switch m.Vulnerability.ID {
		case "CVE-2025-26519":
			found26519 = true
		case "CVE-2025-67499":
			found67499 = true
		}
	}

	assert.False(t, found26519, "expected not to find CVE-2025-26519")
	assert.True(t, found67499, "expected to find CVE-2025-67499")

	doc, sbom, err = sc.ScanSBOM("./testdata/test.spdx.json", nil, "./testdata/empty-vex.json")
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.NotNil(t, sbom)
	assert.Equal(t, 2, sbom.Artifacts.Packages.PackageCount()) // two packages left for test

	matchesWithoutVex := len(doc.Matches)
	found26519 = false
	found67499 = false

	for _, m := range doc.Matches {
		switch m.Vulnerability.ID {
		case "CVE-2025-26519":
			found26519 = true
		case "CVE-2025-67499":
			found67499 = true
		}
	}

	assert.True(t, found26519, "expected to find CVE-2025-26519")
	assert.True(t, found67499, "expected to find CVE-2025-67499")

	assert.Equal(t, 1, matchesWithoutVex-matchesWithVex)
}
