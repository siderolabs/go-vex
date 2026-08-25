// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package kernelversion_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-vex/pkg/kernelversion"
)

func TestParse(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		input   string
		want    kernelversion.Version
		wantErr bool
	}{
		{name: "stable release", input: "6.18.46", want: kernelversion.Version{Major: 6, Minor: 18, Patch: 46}},
		{name: "zero patch", input: "6.18.0", want: kernelversion.Version{Major: 6, Minor: 18, Patch: 0}},
		{name: "multi digit", input: "6.18.140", want: kernelversion.Version{Major: 6, Minor: 18, Patch: 140}},

		// Talos always ships a fully qualified stable release, so anything else
		// is a data error rather than something to interpret.
		{name: "mainline shorthand", input: "6.18", wantErr: true},
		{name: "release candidate", input: "7.1-rc1", wantErr: true},
		{name: "four components", input: "6.12.48.1", wantErr: true},
		{name: "v prefix", input: "v6.18.46", wantErr: true},
		{name: "sentinel zero", input: "0", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "trailing dot", input: "6.18.", wantErr: true},
		{name: "non numeric", input: "6.18.x", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := kernelversion.Parse(test.input)
			if test.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.input, got.String())
		})
	}
}

func TestBranch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "6.18.46", want: "6.18"},
		{input: "6.18.0", want: "6.18"},
		{input: "7.0.11", want: "7.0"},
		{input: "5.15.210", want: "5.15"},
	} {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()

			v, err := kernelversion.Parse(test.input)
			require.NoError(t, err)
			assert.Equal(t, test.want, v.Branch())
		})
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		a, b string
		want int
	}{
		{name: "equal", a: "6.18.46", b: "6.18.46", want: 0},
		{name: "patch less", a: "6.18.41", b: "6.18.42", want: -1},
		{name: "patch greater", a: "6.18.46", b: "6.18.42", want: 1},
		{name: "patch is numeric not lexical", a: "6.18.9", b: "6.18.10", want: -1},
		{name: "minor dominates patch", a: "6.18.99", b: "6.19.0", want: -1},
		{name: "major dominates minor", a: "6.99.0", b: "7.0.0", want: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := kernelversion.CompareVersions(test.a, test.b)
			require.NoError(t, err)
			assert.Equal(t, test.want, got)

			// Comparison must be antisymmetric.
			rev, err := kernelversion.CompareVersions(test.b, test.a)
			require.NoError(t, err)
			assert.Equal(t, -test.want, rev)
		})
	}
}

func TestCompareVersionsInvalid(t *testing.T) {
	t.Parallel()

	_, err := kernelversion.CompareVersions("6.18", "6.18.46")
	require.Error(t, err)

	_, err = kernelversion.CompareVersions("6.18.46", "7.1-rc1")
	require.Error(t, err)
}

func TestVersionInRangeExclusive(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		version    string
		from, to   string
		wantErrStr string
		want       bool
	}{
		// The CVE-2026-53078 case: fixed in 6.18.42 on the 6.18 branch, and in
		// 7.0.10 on the 7.0 branch. 6.19.x never received the backport.
		{name: "fixed on branch", version: "6.18.46", from: "6.18.42", to: "6.19.0", want: true},
		{name: "at lower bound", version: "6.18.42", from: "6.18.42", to: "6.19.0", want: true},
		{name: "below lower bound", version: "6.18.41", from: "6.18.42", to: "6.19.0", want: false},
		{name: "at upper bound is excluded", version: "6.19.0", from: "6.18.42", to: "6.19.0", want: false},
		{name: "above upper bound", version: "6.19.3", from: "6.18.42", to: "6.19.0", want: false},

		{name: "forward range", version: "7.0.11", from: "7.0.10", want: true},
		{name: "forward range below", version: "7.0.9", from: "7.0.10", want: false},
		{name: "unbounded below", version: "6.1.0", to: "6.18.0", want: true},
		{name: "fully unbounded", version: "6.18.46", want: true},

		{name: "invalid version", version: "6.18", from: "6.18.42", wantErrStr: "invalid kernel version"},
		{name: "invalid lower bound", version: "6.18.46", from: "6.18", wantErrStr: "invalid lower bound"},
		{name: "invalid upper bound", version: "6.18.46", from: "6.18.0", to: "6.19", wantErrStr: "invalid upper bound"},
		{name: "empty range", version: "6.18.46", from: "6.19.0", to: "6.18.0", wantErrStr: "empty range"},
		{name: "equal bounds are empty", version: "6.18.46", from: "6.18.42", to: "6.18.42", wantErrStr: "empty range"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := kernelversion.VersionInRangeExclusive(test.version, test.from, test.to)
			if test.wantErrStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErrStr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
