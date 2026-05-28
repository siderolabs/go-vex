// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

// Package v1alpha1 contains data structures for VEX document generation.
package v1alpha1

import (
	"fmt"

	"github.com/openvex/go-vex/pkg/vex"
)

type Statement struct {
	Created       string                `yaml:"created"`                 // RFC3339 date on which the statement was created
	Name          vex.VulnerabilityID   `yaml:"name"`                    // Generally should be CVE name
	Description   string                `yaml:"description"`             // Human-readable description of the statement
	From          string                `yaml:"from"`                    // First version this statement applies to
	To            string                `yaml:"to"`                      // Last version this statement applies to
	Status        vex.Status            `yaml:"status"`                  // not_affected, affected, fixed, under_investigation ...
	StatusNotes   string                `yaml:"statusNotes"`             // Human-readable notes about the status
	Justification vex.Justification     `yaml:"justification,omitempty"` // Justification for the not_affected status
	Impact        string                `yaml:"impact,omitempty"`        // Human-readable impact statement of the vulnerability
	Action        string                `yaml:"action,omitempty"`        // "affected" entries MUST include a statement about mitigation actions
	ActionTime    string                `yaml:"actionTime,omitempty"`    // Time when the action statement was created, RFC3339 format
	LastUpdated   string                `yaml:"lastUpdated,omitempty"`   // Time when the statement was last updated, RFC3339 format
	Aliases       []vex.VulnerabilityID `yaml:"aliases"`                 // Alternative names for the vulnerability
	VersionRanges []string              `yaml:"versionRanges,omitempty"` // ">= vX.Y.Z" constraints; one anchor per X.Y release line. Mutually exclusive with From/To.
}

type ExploitabilityData struct {
	Author     string                        `yaml:"author"`     // Author of the VEX document
	IDs        map[vex.IdentifierType]string `yaml:"ids"`        // IDs (without version) of the product
	Statements []Statement                   `yaml:"statements"` // Statements about vulnerabilities
}

// Validate checks validity of common fields in the ExploitabilityData.
func (d *ExploitabilityData) Validate() error {
	if d.Author == "" {
		return fmt.Errorf("author is required")
	}

	if len(d.IDs) == 0 {
		return fmt.Errorf("at least one product ID is required")
	}

	for i, stmt := range d.Statements {
		if stmt.Created == "" {
			return fmt.Errorf("statement %d: created date is required", i)
		}

		if stmt.Name == "" {
			return fmt.Errorf("statement %d: name is required", i)
		}

		if !stmt.Status.Valid() {
			return fmt.Errorf("statement %d: invalid status %q", i, stmt.Status)
		}

		if stmt.Justification != "" && !stmt.Justification.Valid() {
			return fmt.Errorf("statement %d: invalid justification", i)
		}
	}

	return nil
}
