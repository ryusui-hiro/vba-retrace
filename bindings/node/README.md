# vba-insight (Node.js)

Pure Rust static analysis, P-code disassembly, and VBA Stomping detection for VBA & Office macros (`.xlsm`, `.xlsb`, `.docm`, `.pptm`, `.xls`, `vbaProject.bin`) from Node.js.

Built with N-API. Pre-compiled native binaries for Linux, macOS, and Windows. Zero runtime dependencies.

## Installation

```bash
npm install vba-insight
```

## Quick Start

```javascript
const fs = require('node:fs');
const vbaInsight = require('vba-insight');

// Read any Office macro container (.xlsm, .xlsb, .docm, .pptm, .xls)
const buffer = fs.readFileSync('suspicious.xlsm');

// Inspect container and get complete JSON analysis
const rawJson = vbaInsight.inspectMacroFileJson(buffer);
const report = JSON.parse(rawJson);

console.log('Project Name:', report.project_name);
console.log('Has Stomping:', report.stomping.has_stomping);

// Export SARIF for GitHub Code Scanning
const sarif = vbaInsight.inspectMacroFileSarif(buffer, 'suspicious.xlsm');
fs.writeFileSync('report.sarif', sarif);

// Export Markdown summary
const md = vbaInsight.inspectMacroFileMarkdown(buffer);
console.log(md);
```

## TypeScript

Type definitions are included out of the box in `index.d.ts`.
