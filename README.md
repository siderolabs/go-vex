# go-vex

`go-vex` is a Go library for generating [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) documents from a human-editable YAML data file.

It provides:

* A YAML-based data format (`v1alpha1`) for defining vulnerability exploitability statements across product versions
* Version-range filtering using `git describe`-compatible version strings
* OpenVEX document generation and JSON serialization

## Usage

Load exploitability data from a YAML file and generate a VEX document for a specific product version:

```go
import (
    "os"
    "time"

    "github.com/siderolabs/go-vex/pkg/types/v1alpha1"
    "github.com/siderolabs/go-vex/pkg/vexgen"
)

f, err := os.Open("exploitability.yaml")
if err != nil {
    // handle error
}
defer f.Close()

data, err := v1alpha1.LoadExploitabilityData(f)
if err != nil {
    // handle error
}

now := time.Now()
doc, err := vexgen.Populate(data, "v1.2.0", &now, "my-tool/v1.0.0")
if err != nil {
    // handle error
}

if err := vexgen.Serialize(doc, os.Stdout); err != nil {
    // handle error
}
```

## Data format

The YAML data file contains an author, product identifiers, and a list of vulnerability statements.
Each statement may specify a `from` and/or `to` version to limit its applicability to a version range.

```yaml
author: "Sidero Labs (https://siderolabs.com/)"
ids:
  purl: pkg:generic/myproduct
  cpe23: cpe:2.3:o:example:myproduct
statements:
  - created: 2025-01-01T00:00:00Z
    name: "CVE-2025-12345"
    description: "A vulnerability in library X."
    from: v1.0.0
    to: v1.1.0
    status: "fixed"
    statusNotes: "Patched in v1.1.1."
  - created: 2025-06-01T00:00:00Z
    name: "CVE-2025-99999"
    from: v1.0.0
    status: "not_affected"
    statusNotes: "The affected code path is not compiled into this product."
    justification: "vulnerable_code_not_present"
```

Version strings follow the `git describe` format (e.g. `v1.0.0-35-g46d67fe44`) or plain semver (e.g. `v1.0.0-alpha.1`).
Either `from` or `to` may be omitted to express an open-ended range.

For full details on statement fields, status labels, and justifications, refer to the [OpenVEX v0.2.0 specification](https://github.com/openvex/spec/blob/v0.2.0/OPENVEX-SPEC.md).

## License

`go-vex` is licensed under the [Business Source License 1.1](LICENSE).
