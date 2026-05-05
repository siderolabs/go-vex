// Copyright (c) 2026 Sidero Labs, Inc.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.

package scanner

import "fmt"

// ReportFormat represents the format to output a scanning report in.
type ReportFormat int

const (
	ReportFormatJSON ReportFormat = iota
	ReportFormatTable
	ReportFormatSARIF
	ReportFormatCDX
)

// String returns the string representation of the report format.
func (f ReportFormat) String() string {
	switch f {
	case ReportFormatJSON:
		return "json"
	case ReportFormatTable:
		return "table"
	case ReportFormatSARIF:
		return "sarif"
	case ReportFormatCDX:
		return "cdx"
	default:
		return "unknown"
	}
}

// ParseReportFormat parses a string into a ReportFormat.
func ParseReportFormat(format string) (ReportFormat, error) {
	switch format {
	case "json":
		return ReportFormatJSON, nil
	case "table":
		return ReportFormatTable, nil
	case "sarif":
		return ReportFormatSARIF, nil
	case "cdx":
		return ReportFormatCDX, nil
	default:
		return 0, fmt.Errorf("unknown report format: %s", format)
	}
}
