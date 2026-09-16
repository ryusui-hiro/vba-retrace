# Contributing

Contributions should keep the analyzer deterministic, bounded, and non-executing. The crate reads VBA text and Office containers as data; it must not execute macros, invoke Excel, make network requests, or require proprietary Office components.

Before opening a pull request, run:

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features
cargo package --locked --allow-dirty
```

New parser or semantic rules should include focused synthetic tests and preserve an explicit unresolved result when the host, locale, runtime Variant state, dynamic dispatch, or external type library is required. Resource limits must remain finite for untrusted workbooks. Changes to `.xlsm`, CFB, MS-OVBA, or p-code handling should document the specification or observation source in `docs/PROVENANCE.md`.

Do not commit customer workbooks, extracted VBA source, proprietary opcode tables, or generated build artifacts. Sanitized fixtures must be independently redistributable and should be as small as possible.

The project is MIT licensed. By submitting a contribution, you agree that it may be distributed under that license.
