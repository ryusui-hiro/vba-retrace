# vba-insight (Python)

Pure Rust static analysis, P-code disassembly, and VBA Stomping detection for VBA & Office macros (`.xlsm`, `.xlsb`, `.docm`, `.pptm`, `.xls`, `vbaProject.bin`).

Zero C-library dependencies. Pre-built ABI3 wheels for Linux, macOS, and Windows.

## Installation

```bash
pip install vba-insight
```

## Quick Start

```python
import vba_insight

# Inspect any macro container
report = vba_insight.inspect_file("suspicious.xlsm")

# Check for VBA Stomping / tampering
if report["stomping"]["has_stomping"]:
    print(f"Severity: {report['stomping']['overall_severity']}")
    for finding in report["stomping"]["project_findings"]:
        print(f"Finding: {finding['description']}")

# Export SARIF for GitHub Security / IDEs
sarif = vba_insight.inspect_file_sarif("suspicious.xlsm")

# Export Markdown summary
md = vba_insight.inspect_file_markdown("suspicious.xlsm")
print(md)
```
