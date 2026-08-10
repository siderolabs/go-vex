// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

// Package scanner scans artifacts using Grype.
package scanner

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/pkg"
	cdxPresenter "github.com/anchore/grype/grype/presenter/cyclonedx"
	jsonPresenter "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	sarifPresenter "github.com/anchore/grype/grype/presenter/sarif"
	tablePresenter "github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/wagoodman/go-presenter"
)

// FormatReport formats a scanning report into the specified format and writes into a file.
func FormatReport(modelDocument models.Document, filename string, s *sbom.SBOM, format ReportFormat) error {
	config := models.PresenterConfig{
		Document: modelDocument,
		Pretty:   true,
		SBOM:     s,
	}

	var presenter presenter.Presenter

	switch format {
	case ReportFormatJSON:
		presenter = jsonPresenter.NewPresenter(config)
	case ReportFormatTable:
		// table formatter has no better option to disable color escaping
		os.Setenv("NO_COLOR", "1") //nolint:errcheck

		presenter = tablePresenter.NewPresenter(config, false)
	case ReportFormatSARIF:
		presenter = sarifPresenter.NewPresenter(config)
	case ReportFormatCDX:
		presenter = cdxPresenter.NewJSONPresenter(config)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}

	defer f.Close() //nolint:errcheck

	if err = presenter.Present(f); err != nil {
		return fmt.Errorf("error presenting report file: %w", err)
	}

	return nil
}

// Options are the options for creating a new Scanner.
type Options struct {
	// Distribution is the configuration for the Grype vulnerability database distribution. If nil, the default configuration will be used.
	Distribution *distribution.Config

	// Installation is the configuration for the Grype vulnerability database installation. If nil, the default configuration will be used.
	Installation *installation.Config

	// ID is the identifier for the scanner, used in reports.
	ID string
}

// Scanner is a wrapper around Grype's vulnerability scanner, with added support for VEX data and report formatting.
type Scanner struct {
	db     vulnerability.Provider
	status *vulnerability.ProviderStatus
	id     string
}

// NewScanner creates a scanner with given exploitability data and loads a DB.
func NewScanner(opts Options) (*Scanner, error) {
	distributionConfig := opts.Distribution
	if distributionConfig == nil {
		distributionConfig = new(distribution.DefaultConfig())
	}

	installationConfig := opts.Installation
	if installationConfig == nil {
		installationConfig = new(installation.DefaultConfig(clio.Identification{
			Name: opts.ID,
		}))
	}

	db, status, err := grype.LoadVulnerabilityDB(
		*distributionConfig,
		*installationConfig,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("error loading vulnerability DB: %w", err)
	}

	if status == nil {
		return nil, errors.New("error loading vulnerability DB: no database status reported")
	}

	if status.Error != nil {
		return nil, fmt.Errorf("error loading vulnerability DB: %w", status.Error)
	}

	// the DB path is local to the process that loaded it and says nothing to a
	// report consumer, so keep it out of the reports built from this status.
	status.Path = ""

	return &Scanner{
		id:     opts.ID,
		db:     db,
		status: status,
	}, nil
}

// DatabaseStatus describes the vulnerability database backing the scanner: which
// build it is, where it came from and the provenance of the data feeds in it.
//
// Reports embed it as descriptor.db, matching Grype's own JSON output. Two
// reports that disagree can be told apart by their database build.
type DatabaseStatus struct {
	Status    *vulnerability.ProviderStatus           `json:"status"`
	Providers map[string]vulnerability.DataProvenance `json:"providers"`
}

// DatabaseStatus returns the status of the loaded vulnerability database.
func (sc *Scanner) DatabaseStatus() DatabaseStatus {
	status := DatabaseStatus{
		Status: sc.status,
	}

	if provider, ok := sc.db.(vulnerability.StoreMetadataProvider); ok {
		// provenance is best-effort reporting metadata; a failure here must not
		// fail the scan.
		if provenance, err := provider.DataProvenance(); err == nil {
			status.Providers = provenance
		}
	}

	return status
}

// Close closes the scanner, unloading the vulnerability database.
func (sc *Scanner) Close() error {
	return sc.db.Close()
}

// ScanSBOM scans an SBOM file from path, using a VEX file to determine significance.
func (sc *Scanner) ScanSBOM(sbomPath string, timestamp *time.Time, vexPath ...string) (*models.Document, *sbom.SBOM, error) {
	vexProcessor, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: vexPath,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error initializing Grype VEX processor: %w", err)
	}

	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: sc.db,
		VexProcessor:          vexProcessor,
		Matchers: []match.Matcher{
			golang.NewGolangMatcher(golang.MatcherConfig{
				UseCPEs:               false,
				AlwaysUseCPEForStdlib: true,
			}),
		},
	}

	packages, pkgContext, s, err := pkg.Provide(fmt.Sprintf("sbom:%s", sbomPath), pkg.ProviderConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("error reading SBOM: %w", err)
	}

	matches, _, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return nil, nil, fmt.Errorf("error scanning SBOM: %w", err)
	}

	modelDocument, err := models.NewDocument(
		clio.Identification{
			Name: sc.id,
		},
		packages,
		pkgContext,
		*matches,
		nil, // Do not report vulnerabilities suppressed by VEX (fixed/not_affected)
		sc.db,
		nil,
		sc.DatabaseStatus(),
		models.SortByPackage,
		true,
		&models.DistroAlertData{},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating report: %w", err)
	}

	if timestamp != nil {
		modelDocument.Descriptor.Timestamp = timestamp.Format(time.RFC3339Nano)
	}

	return &modelDocument, s, nil
}
