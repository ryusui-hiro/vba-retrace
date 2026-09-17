# Publishing and releases

## Distribution channels

| Channel | Name | Purpose |
|---|---|---|
| crates.io | `vba-insight` | Core Rust library and `vba-insight` CLI binary |
| PyPI | `vba-insight` | Python binding; import `vba_insight` |
| npm | `vba-insight` | Public Node.js / TypeScript binding |
| GitHub Releases | `vMAJOR.MINOR.PATCH` | Prebuilt CLI archives, ABI3 wheels, npm tarballs, sources, and SHA-256 checksums |
| GitHub Packages | `@ryusui-hiro/vba-insight` | Authenticated npm mirror |

The workflows are prepared independently of registry availability. A configured
publisher does not mean a version is already published. Confirm the version on
each registry before announcing it.

## Authentication setup

References: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
and [PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/).

- **PyPI**: Register `vba-insight` on PyPI with GitHub owner `ryusui-hiro`, repository
  `vba-retrace`, workflow `publish-pypi.yml`, environment `pypi`. A pending
  publisher supports the first release; later releases use the resulting
  project publisher. No long-lived PyPI token is needed.
- **npm**: Bootstrap each new package through an authenticated maintainer publish,
  then configure its GitHub trusted publisher with the same owner/repository,
  workflow `publish-npm.yml`, environment `npm`. Configure the root package and
  every platform package listed in `scripts/release-targets.json`.
- **GitHub Packages**: `publish-github.yml` uses the job's short-lived
  `GITHUB_TOKEN` with `packages: write`, in environment `github-packages`.
- **crates.io**: Use GitHub Actions OIDC via `rust-lang/crates-io-auth-action`
  or maintainer's local Cargo authentication for the first release. Never put
  credentials in repository code or release assets.

Create the named GitHub environments (`pypi`, `npm`, `crates-io`, `github-packages`)
and restrict publishing to the protected `main` branch.

## Release procedure

1. **Version Alignment**:
   Update the version synchronously across:
   - Root `Cargo.toml`
   - `bindings/python/pyproject.toml`
   - `bindings/python/Cargo.toml`
   - `bindings/node/package.json`
   - `bindings/node/Cargo.toml`
   
   Verify alignment with:
   ```bash
   python3 -c "import importlib.util; spec = importlib.util.spec_from_file_location('r', 'scripts/release-artifacts.py'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print('Release version:', m.version())"
   ```

2. **Run Release Build**:
   Merge tested changes into `main`. Trigger **Build release artifacts** (`build-release.yml`).
   This builds native CLI binaries, Python ABI3 wheels, and Node N-API addons across 8 matrix targets:
   - Linux x86_64 (glibc & musl)
   - Linux aarch64 (glibc & musl)
   - macOS x86_64 (Intel)
   - macOS aarch64 (Apple Silicon)
   - Windows x86_64
   - Windows aarch64

3. **Assemble Distribution**:
   Download the artifacts from the successful run and assemble:
   ```bash
   gh run download <RUN_ID> --dir dist/downloaded
   python3 scripts/release-artifacts.py assemble \
     --artifacts dist/downloaded --output dist/release \
     --commit <FULL_COMMIT_SHA>
   ```

4. **GitHub Release**:
   Create a git tag (e.g. `v0.1.0`) and draft a GitHub Release.
   Upload the top-level files from `dist/release` (including `release-manifest.json`, wheels, npm tarballs, and CLI zip archives).

5. **Publish to Registries**:
   Dispatch the publishing workflows providing the release tag:
   - **Publish PyPI** (`publish-pypi.yml`)
   - **Publish npm** (`publish-npm.yml`)
   - **Publish crates.io** (`publish-crates.yml`)

Each publishing workflow verifies cryptographic SHA-256 hashes against `release-manifest.json` and ensures the commit SHA strictly matches before uploading.
