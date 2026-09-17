# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature from the repository's **Security** tab. Do not report exploitable details in a public issue or attach a workbook that contains confidential data.

Include the affected release or commit, Rust version, a short impact description, and a minimal sanitized input when possible. This project reads VBA source and Office containers as data; it does not execute macros or make network requests. Keep finite parser resource limits enabled when processing untrusted files.

## Supported versions

Security fixes are made on the latest development version. Pre-1.0 releases may not receive backports.
