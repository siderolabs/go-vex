// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package gitversion_test

import (
	"testing"

	"github.com/siderolabs/go-vex/pkg/gitversion"
)

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		// Valid semantic versions
		{"basic semantic version", "v1.0.0", true},
		{"semantic version with patch", "v2.3.4", true},
		{"semantic version with large numbers", "v10.20.30", true},
		{"semantic version with dirty suffix", "v10.20.30-dirty", true},

		// Valid semantic versions with prereleases
		{"alpha prerelease", "v1.0.0-alpha.1", true},
		{"beta prerelease", "v1.0.0-beta.2", true},
		{"rc prerelease", "v1.0.0-rc.3", true},
		{"alpha with larger number", "v2.1.0-alpha.10", true},
		{"beta with dirty suffix", "v2.1.0-beta.1-dirty", true},

		// Valid versions with git suffixes
		{"version with git suffix", "v1.0.0-35-g46d67fe44", true},
		{"alpha with git suffix", "v1.0.0-alpha.1-12-gabcdef123", true},
		{"beta with git suffix", "v1.2.3-beta.2-99-gdeadbeef", true},
		{"rc with git suffix", "v2.0.0-rc.1-7-g1234567", true},
		{"version with zero commits", "v1.0.0-0-g123456789", true},
		{"version with large commit count and dirty suffix", "v1.11.0-alpha.3-12521-g3e3163436-dirty", true},

		// Invalid versions
		{"missing v prefix", "1.0.0", false},
		{"incomplete version", "v1.0", false},
		{"non-numeric major", "va.0.0", false},
		{"non-numeric minor", "v1.a.0", false},
		{"non-numeric patch", "v1.0.a", false},
		{"invalid prerelease type", "v1.0.0-gamma.1", false},
		{"missing prerelease number", "v1.0.0-alpha", false},
		{"non-numeric prerelease", "v1.0.0-alpha.a", false},
		{"invalid git suffix format", "v1.0.0-abc-gabcdef", false},
		{"missing git hash", "v1.0.0-35-", false},
		{"invalid git hash prefix", "v1.0.0-35-x46d67fe44", false},
		{"invalid extra suffix", "v1.0.0-35-g46d67fe44-extra", false},
		{"empty string", "", false},
		{"not a version", "not-a-version", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gitversion.ValidateVersion(tt.version)
			if result != tt.expected {
				t.Errorf("ValidateVersion(%q) = %v; want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestStripGitSuffix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.0.0-35-g46d67fe44", "v1.0.0"},
		{"v1.0.0-alpha.1-12-gabcdef123", "v1.0.0-alpha.1"},
		{"v2.3.4", "v2.3.4"},
		{"v0.1.0-0-g123456789", "v0.1.0"},
		{"v1.2.3-beta.2-99-gdeadbeef", "v1.2.3-beta.2"},
		{"not-a-version", "not-a-version"},
		{"v1.0.0-35-g46d67fe44-extra", "v1.0.0-35-g46d67fe44-extra"},
		{"v1.0.0-35-g46d67fe44-dirty", "v1.0.0"},
		{"v42.626.42-rc.1-dirty", "v42.626.42-rc.1"},
	}

	for _, tt := range tests {
		result := gitversion.StripGitSuffix(tt.input)
		if result != tt.expected {
			t.Errorf("StripGitSuffix(%q) = %q; want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		// Semantic version comparisons
		{"newer major version", "v2.0.0", "v1.0.0", 1},
		{"older major version", "v1.0.0", "v2.0.0", -1},
		{"newer minor version", "v1.1.0", "v1.0.0", 1},
		{"older minor version", "v1.0.0", "v1.1.0", -1},
		{"newer patch version", "v1.0.1", "v1.0.0", 1},
		{"older patch version", "v1.0.0", "v1.0.1", -1},
		{"equal versions", "v1.0.0", "v1.0.0", 0},
		{"prerelease vs release", "v1.0.0-alpha.1", "v1.0.0", -1},
		{"release vs prerelease", "v1.0.0", "v1.0.0-alpha.1", 1},
		{"alpha vs beta", "v1.0.0-alpha.1", "v1.0.0-beta.1", -1},
		{"beta vs alpha", "v1.0.0-rc.1", "v1.0.0-beta.1", 1},
		{"same versions", "v1.0.0", "v1.0.0", 0},
		{"a < b semver", "v1.0.0", "v1.1.0", -1},
		{"a > b semver", "v1.1.0", "v1.0.0", 1},
		{"different prereleases", "v1.0.0-alpha.1", "v1.0.0-beta.1", -1},

		// Git commit count comparisons with same semver
		{"same semver, a has commits", "v1.0.0-5-gabcdef", "v1.0.0", 1},
		{"same semver, b has commits", "v1.0.0", "v1.0.0-10-gabcdef", -1},
		{"same semver, different commit counts", "v1.0.0-5-gabcdef", "v1.0.0-10-gabcdef", -1},
		{"same semver, different commit counts, B", "v1.0.0-895-gabcdef", "v1.0.0-1-gabcdef", 1},
		{"same semver, same commit counts", "v1.0.0-5-gabcdef", "v1.0.0-5-g123456", 0},

		// Different semver with git revisions
		{"prerelease with commits", "v1.0.0-alpha.1-5-g12345", "v1.0.0-alpha.1-3-g67890", 1},
		{"prerelease tag vs commits", "v1.0.0-alpha.1", "v1.0.0-alpha.1-5-g12345", -1},
		{"different semver with git", "v1.1.0-5-g12345", "v1.0.0-10-g67890", 1},
		{"different prerelease with git", "v1.0.0-beta.1-5-g12345", "v1.0.0-alpha.1-10-g67890", 1},

		// Prerelease with git commits
		{"prerelease with commits vs without", "v1.0.0-alpha.1-5-gabcdef", "v1.0.0-alpha.1", 1},
		{"same prerelease, different commit counts", "v1.0.0-alpha.1-5-gabcdef", "v1.0.0-alpha.1-10-gabcdef", -1},

		// Same revision, but dirty tree makes it newer
		{"same version, dirty suffix", "v1.0.0-5-gabcdef", "v1.0.0-5-gabcdef-dirty", -1},
		{"dirty suffix vs clean", "v1.0.0-5-gabcdef-dirty", "v1.0.0-5-gabcdef", 1},
		{"same rev, dirty suffix vs dirty suffix", "v1.0.0-5-gabcdef-dirty", "v1.0.0-5-g123456-dirty", 0},
		{"different versions, dirty", "v1.0.0-3-gabcdef-dirty", "v1.0.0-5-g123456-dirty", -1},
		{"dirty for plain semver", "v1.0.0-dirty", "v1.0.0", 1},
		{"dirty for plain semver, reverse", "v1.0.0", "v1.0.0-dirty", -1},

		// Edge cases
		{"no git suffix in either", "v1.0.0", "v1.0.0", 0},

		// Plain string comparison for invalid versions
		{"invalid revision", "v1.0.0-abc-gabcdef", "v1.0.0", 1},
		{"both invalid revisions", "v1.0.0-abc-gabcdef", "v1.0.0-def-g123456", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gitversion.CompareVersions(tt.a, tt.b)

			if result != tt.expected {
				t.Errorf("CompareVersions(%q, %q) = %d; want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestVersionInRange(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		from        string
		to          string
		expected    bool
		expectError bool
	}{
		// Valid ranges - version within range
		{"version in range - basic", "v1.5.0", "v1.0.0", "v2.0.0", true, false},
		{"version at lower bound", "v1.0.0", "v1.0.0", "v2.0.0", true, false},
		{"version at upper bound", "v2.0.0", "v1.0.0", "v2.0.0", true, false},
		{"version in range - same versions", "v1.0.0", "v1.0.0", "v1.0.0", true, false},
		{"version in range - prereleases", "v1.0.0-beta.1", "v1.0.0-alpha.1", "v1.0.0-rc.1", true, false},
		{"version in range - prereleases at bounds", "v1.0.0-alpha.1", "v1.0.0-alpha.1", "v1.0.0-rc.1", true, false},
		{"version in range - with git suffix", "v1.0.0-7-gabcdef999", "v1.0.0-5-gabcdef999", "v1.0.0-10-g123456999", true, false},

		// Valid ranges - version outside range
		{"version before range", "v0.9.0", "v1.0.0", "v2.0.0", false, false},
		{"version after range", "v2.1.0", "v1.0.0", "v2.0.0", false, false},
		{"prerelease before range", "v0.9.0-alpha.1", "v1.0.0", "v2.0.0", false, false},
		{"prerelease after range", "v2.1.0-alpha.1", "v1.0.0", "v2.0.0", false, false},
		{"version before prerelease range", "v1.0.0-alpha.1", "v1.0.0-beta.1", "v1.0.0-rc.1", false, false},
		{"version after prerelease range", "v1.0.0-rc.2", "v1.0.0-alpha.1", "v1.0.0-rc.1", false, false},

		// Valid ranges, only one side specified
		{"only from specified - in range", "v1.5.0", "v1.0.0", "", true, false},
		{"only from specified - at bound", "v1.0.0", "v1.0.0", "", true, false},
		{"only from specified - below bound, alpha", "v1.0.0-alpha.2-20-g222", "v1.0.0", "", false, false},
		{"only from specified - before range", "v0.9.0", "v1.0.0", "", false, false},
		{"only to specified - in range", "v1.5.0-alpha.1", "", "v2.0.0", true, false},
		{"only to specified - at bound", "v2.0.0", "", "v2.0.0", true, false},
		{"only to specified - after range", "v2.1.0", "", "v2.0.0", false, false},
		{"only to specified - after range, rc", "v2.1.0-rc.2-44-g123456", "", "v2.0.0", false, false},
		{"only from specified - invalid version", "v1.5.0", "invalid-version", "", false, true},

		// Unbounded ranges
		{"unbounded range 1", "v1.5.0", "", "", true, false},
		{"unbounded range 2", "v2.1.3-beta.3-43-g111-dirty", "", "", true, false},

		// Invalid version formats
		{"invalid version format", "1.0.0", "v1.0.0", "v2.0.0", false, true},
		{"invalid from format", "v1.0.0", "1.0.0", "v2.0.0", false, true},
		{"invalid to format", "v1.0.0", "v1.0.0", "2.0.0", false, true},
		{"all invalid formats", "1.0.0", "1.0.0", "2.0.0", false, true},
		{"empty version", "", "v1.0.0", "v2.0.0", false, true},
		{"non-version string", "not-a-version", "v1.0.0", "v2.0.0", false, true},

		// Edge cases with prereleases
		{"release vs prerelease range", "v1.0.0", "v1.0.0-alpha.1", "v1.0.0-rc.1", false, false},
		{"prerelease vs release range", "v1.0.0-beta.1", "v1.0.0-alpha.7", "v2.0.0", true, false},

		// Invalid ranges
		{"invalid range - from > to", "v1.5.0", "v2.0.0", "v1.0.0", false, true},

		// Complex version comparisons
		{"version with git suffix in range", "v1.5.0-10-gabcdef", "v1.0.0", "v2.0.0", true, false},
		{"version with git suffix before range", "v0.9.0-5-g123456", "v1.0.0", "v2.0.0", false, false},
		{"version with git suffix after range", "v2.1.0-5-g123456", "v1.0.0", "v2.0.0", false, false},
		{"all versions with git suffixes", "v1.5.0-5-gabcdef", "v1.0.0-3-g123456", "v2.0.0-10-gdeadbeef", true, false},

		// Additional alpha/beta prerelease tests
		{"alpha version sequence in range", "v1.0.0-alpha.5", "v1.0.0-alpha.1", "v1.0.0-alpha.10", true, false},
		{"beta version sequence in range", "v1.0.0-beta.3", "v1.0.0-beta.1", "v1.0.0-beta.5", true, false},
		{"rc version sequence in range", "v1.0.0-rc.2", "v1.0.0-rc.1", "v1.0.0-rc.3", true, false},
		{"alpha before beta range", "v1.0.0-alpha.9", "v1.0.0-beta.1", "v1.0.0-beta.5", false, false},
		{"beta after alpha range", "v1.0.0-beta.1", "v1.0.0-alpha.1", "v1.0.0-alpha.9", false, false},
		{"rc in beta-rc range", "v1.0.0-rc.1", "v1.0.0-beta.5", "v1.0.0-rc.3", true, false},
		{"mixed prerelease types", "v1.0.0-beta.2", "v1.0.0-alpha.10", "v1.0.0-rc.1", true, false},

		// Alpha/beta with commit revision tests
		{"alpha with commits in range", "v1.0.0-alpha.1-5-gabcdef", "v1.0.0-alpha.1-3-g123456", "v1.0.0-alpha.1-10-gdeadbe", true, false},
		{"beta with commits in range", "v1.0.0-beta.2-7-gabcdef", "v1.0.0-beta.2-5-g123456", "v1.0.0-beta.2-10-gdeadbe", true, false},
		{"alpha with commits vs tag", "v1.0.0-alpha.1-5-gabcdef", "v1.0.0-alpha.1", "v1.0.0-alpha.2", true, false},
		{"beta tag vs commits", "v1.0.0-beta.1", "v1.0.0-alpha.1-5-gabcdef", "v1.0.0-beta.2", true, false},
		{"prerelease with commits before range", "v1.0.0-alpha.1-2-gabcdef", "v1.0.0-alpha.1-5-g123456", "v1.0.0-alpha.2", false, false},
		{"prerelease with commits after range", "v1.0.0-beta.1-15-gabcdef", "v1.0.0-alpha.1", "v1.0.0-beta.1-10-g123456", false, false},

		// Dirty suffix tests
		{"dirty version in range", "v1.5.0-dirty", "v1.0.0", "v2.0.0", true, false},
		{"dirty version at bounds", "v1.0.0-dirty", "v1.0.0", "v2.0.0", true, false},
		{"dirty version before range", "v0.9.0-dirty", "v1.0.0", "v2.0.0", false, false},
		{"dirty version after range", "v2.1.0-dirty", "v1.0.0", "v2.0.0", false, false},
		{"clean vs dirty same version", "v1.0.0", "v1.0.0-dirty", "v2.0.0", false, false},
		{"dirty vs clean same version upper", "v2.0.0-dirty", "v1.0.0", "v2.0.0", false, false},
		{"all dirty versions", "v1.5.0-dirty", "v1.0.0-dirty", "v2.0.0-dirty", true, false},

		// Prerelease with dirty suffix
		{"dirty alpha in range", "v1.0.0-alpha.5-dirty", "v1.0.0-alpha.1", "v1.0.0-beta.1", true, false},
		{"dirty beta in range", "v1.0.0-beta.2-dirty", "v1.0.0-beta.1", "v1.0.0-rc.1", true, false},
		{"dirty alpha vs clean beta", "v1.0.0-alpha.1-dirty", "v1.0.0-alpha.1", "v1.0.0-beta.1", true, false},
		{"clean alpha vs dirty beta", "v1.0.0-beta.1", "v1.0.0-alpha.1-dirty", "v1.0.0-rc.1", true, false},

		// Git commits with dirty suffix
		{"dirty commits in range", "v1.0.0-5-gabcdef-dirty", "v1.0.0-3-g123456", "v1.0.0-10-gdeadbe", true, false},
		{"clean vs dirty same commits", "v1.0.0-5-gabcdef", "v1.0.0-5-gabcdef-dirty", "v1.0.0-10-g123456", false, false},
		{"dirty vs clean same commits upper", "v1.0.0-10-gabcdef-dirty", "v1.0.0-5-g123456", "v1.0.0-10-gabcdef", false, false},
		{"prerelease with commits and dirty", "v1.0.0-alpha.1-5-gabcdef-dirty", "v1.0.0-alpha.1-3-g123456", "v1.0.0-alpha.2", true, false},

		// Complex mixed scenarios
		{"clean release vs dirty prerelease range", "v1.1.0", "v1.0.0-alpha.1-dirty", "v1.2.0-beta.1-dirty", true, false},
		{"dirty prerelease vs clean commit range", "v1.0.0-beta.1-dirty", "v1.0.0-5-gabcdef", "v1.1.0-10-g123456", false, false},
		{"mixed dirty and clean boundaries", "v1.5.0-7-gabcdef", "v1.0.0-dirty", "v2.0.0-5-g123456-dirty", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gitversion.VersionInRange(tt.version, tt.from, tt.to)

			if tt.expectError {
				if err == nil {
					t.Errorf("VersionInRange(%q, %q, %q) expected error but got none", tt.version, tt.from, tt.to)
				}

				return
			}

			if err != nil {
				t.Errorf("VersionInRange(%q, %q, %q) unexpected error: %v", tt.version, tt.from, tt.to, err)

				return
			}

			if result != tt.expected {
				t.Errorf("VersionInRange(%q, %q, %q) = %v; want %v", tt.version, tt.from, tt.to, result, tt.expected)
			}
		})
	}
}

func TestVersionInRangeExclusive(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		from        string
		to          string
		expected    bool
		expectError bool
	}{
		// Core exclusive-upper semantics.
		{"version equal to upper bound is excluded", "v2.0.0", "v1.0.0", "v2.0.0", false, false},
		{"version equal to lower bound is included", "v1.0.0", "v1.0.0", "v2.0.0", true, false},
		{"version strictly inside range", "v1.5.0", "v1.0.0", "v2.0.0", true, false},
		{"version one patch below upper still in range", "v1.9.999", "v1.0.0", "v2.0.0", true, false},

		// Pre-release boundaries (where ordering matters most).
		{"upper bound pre-release excludes itself", "v1.14.0-alpha.0", "v1.13.0", "v1.14.0-alpha.0", false, false},
		{"version just below pre-release upper", "v1.13.999", "v1.13.0", "v1.14.0-alpha.0", true, false},
		{"release excluded by pre-release upper", "v1.14.0", "v1.13.0", "v1.14.0-alpha.0", false, false},
		{"alpha lower included", "v1.14.0-alpha.0", "v1.14.0-alpha.0", "v1.14.0", true, false},

		// Unbounded ranges still behave like VersionInRange.
		{"unbounded above: version equals from", "v1.0.0", "v1.0.0", "", true, false},
		{"unbounded above: version far above from", "v9.9.9", "v1.0.0", "", true, false},
		{"unbounded above: version below from", "v0.9.0", "v1.0.0", "", false, false},
		{"unbounded below: version below to", "v1.9.999", "", "v2.0.0", true, false},
		{"unbounded below: version equal to is excluded", "v2.0.0", "", "v2.0.0", false, false},
		{"fully unbounded matches anything", "v1.5.0", "", "", true, false},
		{"fully unbounded matches git-described version", "v1.13.0-alpha.0-12-gabcdef", "", "", true, false},

		// Outside-range cases.
		{"version below from", "v0.9.0", "v1.0.0", "v2.0.0", false, false},
		{"version above to", "v2.1.0", "v1.0.0", "v2.0.0", false, false},

		// Error pass-through from VersionInRange.
		{"invalid version", "not-a-version", "v1.0.0", "v2.0.0", false, true},
		{"invalid from", "v1.0.0", "garbage", "v2.0.0", false, true},
		{"invalid to", "v1.0.0", "v1.0.0", "garbage", false, true},
		{"from greater than to", "v1.5.0", "v2.0.0", "v1.0.0", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gitversion.VersionInRangeExclusive(tt.version, tt.from, tt.to)

			if tt.expectError {
				if err == nil {
					t.Errorf("VersionInRangeExclusive(%q, %q, %q) expected error but got none", tt.version, tt.from, tt.to)
				}

				return
			}

			if err != nil {
				t.Errorf("VersionInRangeExclusive(%q, %q, %q) unexpected error: %v", tt.version, tt.from, tt.to, err)

				return
			}

			if result != tt.expected {
				t.Errorf("VersionInRangeExclusive(%q, %q, %q) = %v; want %v", tt.version, tt.from, tt.to, result, tt.expected)
			}
		})
	}
}
