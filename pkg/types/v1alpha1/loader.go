// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1

import (
	"fmt"
	"io"

	"github.com/openvex/go-vex/pkg/vex"
	"go.yaml.in/yaml/v4"
)

// Option is a functional option manipulating ExploitabilityData.
type Option func(*ExploitabilityData)

// WithPURLOverride allows overriding the PURL in the ExploitabilityData.
func WithPURLOverride(purl string) Option {
	return func(data *ExploitabilityData) {
		if data.IDs == nil {
			data.IDs = make(map[vex.IdentifierType]string)
		}

		data.IDs[vex.PURL] = purl
	}
}

// LoadExploitabilityData loads VEX data from an io.Reader.
// The data should be in YAML format matching ExploitabilityData structure.
//
// Statements that declare VersionRanges are expanded into one bounded
// Statement per release line via Expand before the data is returned.
func LoadExploitabilityData(reader io.Reader, opts ...Option) (*ExploitabilityData, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading data: %w", err)
	}

	var raw ExploitabilityData
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("error unmarshalling data: %w", err)
	}

	result := ExploitabilityData{
		Author:     raw.Author,
		IDs:        raw.IDs,
		Statements: make([]Statement, 0, len(raw.Statements)),
	}

	for i, stmt := range raw.Statements {
		expanded, err := Expand(stmt)
		if err != nil {
			return nil, statementError(i, stmt, err)
		}

		result.Statements = append(result.Statements, expanded...)
	}

	// Apply options to the loaded data.
	for _, opt := range opts {
		opt(&result)
	}

	return &result, nil
}
