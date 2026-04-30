// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package v1alpha1

import (
	"fmt"
	"io"

	"go.yaml.in/yaml/v4"
)

// LoadExploitabilityData loads VEX data from an io.Reader.
// The data should be in YAML format matching ExploitabilityData structure.
func LoadExploitabilityData(reader io.Reader) (*ExploitabilityData, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading data: %w", err)
	}

	var result ExploitabilityData
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshalling data: %w", err)
	}

	return &result, nil
}
