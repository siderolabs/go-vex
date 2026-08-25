// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

// Package vexgen generates an OpenVEX-formatted file from the given advisory information.
package vexgen

import (
	"fmt"
	"io"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/siderolabs/go-vex/pkg/gitversion"
	"github.com/siderolabs/go-vex/pkg/kernelversion"
	"github.com/siderolabs/go-vex/pkg/types/v1alpha1"
)

// Options control how statements are selected for a target.
type Options struct {
	// KernelVersion is the Linux kernel version shipped by the target, as
	// X.Y.Z. When empty, statements declaring kernelVersionRanges are skipped,
	// because there is nothing to compare them against.
	KernelVersion string
}

// Option configures Options.
type Option func(*Options)

// WithKernelVersion sets the Linux kernel version shipped by the target, so
// that statements declaring kernelVersionRanges can be evaluated.
func WithKernelVersion(version string) Option {
	return func(o *Options) {
		o.KernelVersion = version
	}
}

func makeOptions(opts ...Option) Options {
	var o Options

	for _, opt := range opts {
		opt(&o)
	}

	return o
}

// Populate generates a VEX document from the provided exploitability data
// for the given product version.
func Populate(data *v1alpha1.ExploitabilityData, productVersion string, timestamp *time.Time, tooling string, opts ...Option) (vex.VEX, error) {
	doc := vex.New()
	doc.Author = data.Author

	doc.Version = 1

	doc.Tooling = tooling
	if timestamp != nil {
		doc.Timestamp = timestamp
	}

	productIDs := MakeVersionedProductIDs(data.IDs, productVersion)

	var err error

	doc.Statements, err = ConvertStatements(data.Statements, productIDs, productVersion, opts...)
	if err != nil {
		return doc, fmt.Errorf("error converting statement: %w", err)
	}

	return doc, nil
}

// Serialize serializes the VEX document to the provided writer in JSON format, with a reproducible ID.
func Serialize(doc vex.VEX, writer io.Writer) error {
	_, err := doc.GenerateCanonicalID()
	if err != nil {
		return fmt.Errorf("error generating document ID: %w", err)
	}

	if err := doc.ToJSON(writer); err != nil {
		return fmt.Errorf("error converting document to JSON: %w", err)
	}

	return nil
}

// MakeVersionedProductIDs adds the product version to provided identifiers.
func MakeVersionedProductIDs(ids map[vex.IdentifierType]string, productVersion string) map[vex.IdentifierType]string {
	productIDs := make(map[vex.IdentifierType]string)

	for id, idValue := range ids {
		switch id {
		case vex.PURL:
			productIDs[id] = fmt.Sprintf("%s@%s", idValue, productVersion)
		case vex.CPE22, vex.CPE23:
			productIDs[id] = fmt.Sprintf("%s:%s:*:*:*:*:*:*:*", idValue, productVersion)
		}
	}

	return productIDs
}

// statementApplies reports whether a statement applies to the target.
//
// A statement declaring kernelVersionRanges is matched on the kernel version
// and applies if the target kernel falls in any of its ranges; everything else
// is matched on the Talos product version.
func statementApplies(stmt v1alpha1.Statement, productVersion string, options Options) (bool, error) {
	if len(stmt.KernelVersionRanges) == 0 {
		inRange, err := gitversion.VersionInRangeExclusive(productVersion, stmt.From, stmt.To)
		if err != nil {
			return false, fmt.Errorf("error checking version range: %w", err)
		}

		return inRange, nil
	}

	// Without a kernel version there is nothing to compare against, so the
	// statement cannot be shown to apply.
	if options.KernelVersion == "" {
		return false, nil
	}

	for _, c := range stmt.KernelVersionRanges {
		from, to, err := v1alpha1.ParseKernelRange(c)
		if err != nil {
			return false, fmt.Errorf("error parsing kernel version range for %s: %w", stmt.Name, err)
		}

		inRange, err := kernelversion.VersionInRangeExclusive(options.KernelVersion, from, to)
		if err != nil {
			return false, fmt.Errorf("error checking kernel version range for %s: %w", stmt.Name, err)
		}

		if inRange {
			return true, nil
		}
	}

	return false, nil
}

// ConvertStatements converts the provided statement data to VEX statements,
// filtering out statements that do not apply to the specified product version.
//
// A statement declaring kernelVersionRanges is selected by comparing the
// kernel version supplied via WithKernelVersion instead of the product
// version. Without that option such statements are skipped, since there is
// nothing to compare them against.
func ConvertStatements(
	statements []v1alpha1.Statement,
	productIDs map[vex.IdentifierType]string,
	productVersion string,
	opts ...Option,
) ([]vex.Statement, error) {
	options := makeOptions(opts...)

	result := make([]vex.Statement, 0, len(statements))

	for _, stmt := range statements {
		inRange, err := statementApplies(stmt, productVersion, options)
		if err != nil {
			return result, err
		} else if !inRange {
			continue
		}

		createdTime, err := time.Parse(time.RFC3339, stmt.Created)
		if err != nil {
			return result, fmt.Errorf("error parsing time: %w", err)
		}

		var actionTime *time.Time

		if stmt.ActionTime != "" {
			actionTimeParsed, err := time.Parse(time.RFC3339, stmt.ActionTime)
			if err != nil {
				return result, fmt.Errorf("error parsing action time: %w", err)
			}

			actionTime = &actionTimeParsed
		}

		var lastUpdated *time.Time

		if stmt.LastUpdated != "" {
			lastUpdatedParsed, err := time.Parse(time.RFC3339, stmt.LastUpdated)
			if err != nil {
				return result, fmt.Errorf("error parsing last updated time: %w", err)
			}

			lastUpdated = &lastUpdatedParsed
		}

		entry := vex.Statement{
			Vulnerability: vex.Vulnerability{
				Name:        stmt.Name,
				Description: stmt.Description,
				Aliases:     stmt.Aliases,
			},
			Products: []vex.Product{
				{
					Component: vex.Component{
						Identifiers: productIDs,
					},
				},
			},
			Status:                   stmt.Status,
			StatusNotes:              stmt.StatusNotes,
			Timestamp:                &createdTime,
			Justification:            stmt.Justification,
			ImpactStatement:          stmt.Impact,
			ActionStatement:          stmt.Action,
			ActionStatementTimestamp: actionTime,
			LastUpdated:              lastUpdated,
		}

		if err := entry.Validate(); err != nil {
			return result, fmt.Errorf("invalid statement: %w", err)
		}

		result = append(result, entry)
	}

	return result, nil
}
