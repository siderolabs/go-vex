// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package kernelversion

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FromSPDXJSON returns the kernel package version from an SPDX JSON document.
//
// SPDX represents an X.Y.0 kernel as X.Y, so the implicit patch component is
// restored before validation. An empty result means the document has no kernel
// package, as is expected for a Talos container SBOM. Duplicate kernel packages
// are accepted only when their versions agree.
func FromSPDXJSON(data []byte) (string, error) {
	var document struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"versionInfo"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &document); err != nil {
		return "", fmt.Errorf("error decoding SPDX JSON: %w", err)
	}

	var kernelVersion string

	for _, pkg := range document.Packages {
		if pkg.Name != "kernel" {
			continue
		}

		version := pkg.Version
		if strings.Count(version, ".") == 1 {
			version += ".0"
		}

		parsed, err := Parse(version)
		if err != nil {
			return "", fmt.Errorf("invalid kernel package version: %w", err)
		}

		version = parsed.String()

		switch {
		case kernelVersion == "":
			kernelVersion = version
		case kernelVersion != version:
			return "", fmt.Errorf(
				"conflicting kernel package versions %q and %q",
				kernelVersion,
				version,
			)
		}
	}

	return kernelVersion, nil
}
