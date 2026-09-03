// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package kernelversion_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-vex/pkg/kernelversion"
)

func TestFromSPDXJSON(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		json    string
		want    string
		wantErr string
	}{
		{
			name: "kernel patch release",
			json: spdxPackages(
				`{"name":"musl","versionInfo":"1.2.5"}`,
				`{"name":"kernel","versionInfo":"6.18.46"}`,
			),
			want: "6.18.46",
		},
		{
			name: "kernel dot zero release",
			json: spdxPackages(
				`{"name":"kernel","versionInfo":"6.18"}`,
			),
			want: "6.18.0",
		},
		{
			name: "matching duplicate packages",
			json: spdxPackages(
				`{"name":"kernel","versionInfo":"6.18"}`,
				`{"name":"kernel","versionInfo":"6.18.0"}`,
			),
			want: "6.18.0",
		},
		{
			name: "container SBOM has no kernel",
			json: spdxPackages(
				`{"name":"musl","versionInfo":"1.2.5"}`,
			),
		},
		{
			name:    "conflicting kernel packages",
			json:    spdxPackages(`{"name":"kernel","versionInfo":"6.18.46"}`, `{"name":"kernel","versionInfo":"6.18.47"}`),
			wantErr: `conflicting kernel package versions "6.18.46" and "6.18.47"`,
		},
		{
			name:    "invalid kernel version",
			json:    spdxPackages(`{"name":"kernel","versionInfo":"6.18.46-talos"}`),
			wantErr: `invalid kernel package version: invalid kernel version "6.18.46-talos"`,
		},
		{
			name:    "malformed JSON",
			json:    `{`,
			wantErr: "error decoding SPDX JSON",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := kernelversion.FromSPDXJSON([]byte(test.json))
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, test.want, got)
		})
	}
}

func spdxPackages(packages ...string) string {
	return `{"spdxVersion":"SPDX-2.3","packages":[` + strings.Join(packages, ",") + `]}`
}
