"""Publish checksum-verified release tarballs, native dependencies first.

PUBLIC_REGISTRY is npm or github. GitHub Actions supplies OIDC for npm and an
ephemeral GITHUB_TOKEN for GitHub Packages; this script stores no credentials.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

repo = os.environ.get('GITHUB_REPOSITORY', 'ryusui-hiro/vba-retrace')
kind = os.environ.get('PUBLIC_REGISTRY', 'npm')
if kind not in ('npm', 'github'):
    raise SystemExit('unknown registry')
registry = 'https://registry.npmjs.org' if kind == 'npm' else 'https://npm.pkg.github.com'
tag = os.environ['RELEASE_TAG']
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
    raise SystemExit('invalid release tag')
version = tag[1:]
destination = Path('dist') / f'publish-{kind}'
destination.mkdir(parents=True, exist_ok=True)
prefix = 'vba-insight-' if kind == 'npm' else 'ryusui-hiro-vba-insight-'
subprocess.run(['gh', 'release', 'download', tag, '--repo', repo, '--dir', str(destination),
                '--pattern', prefix + '*.tgz', '--pattern', 'release-manifest.json'], check=True)
manifest = json.loads((destination / 'release-manifest.json').read_text())
ref = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repo}/git/ref/tags/{tag}']))['object']
if ref['type'] == 'tag':
    ref = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repo}/git/tags/{ref["sha"]}']))['object']
if ref['sha'] != manifest['commit'] or manifest['version'] != version:
    raise SystemExit('release source mismatch')
targets = json.loads(Path('scripts/release-targets.json').read_text())
root_name = 'vba-insight' if kind == 'npm' else '@ryusui-hiro/vba-insight'
expected_names = {root_name} | {root_name + '-' + target['tag'] for target in targets}
artifacts = []
for path in destination.glob('*.tgz'):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest['files'].get(path.name):
        raise SystemExit(f'checksum mismatch: {path.name}')
    with tarfile.open(path) as archive:
        package = json.loads(archive.extractfile('package/package.json').read())
        for license in ('LICENSE',):
            archive.getmember('package/' + license)
    if package['version'] != version or package['name'] not in expected_names:
        raise SystemExit(f'unexpected npm package identity: {package["name"]} (expected one of {expected_names})')
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()
    artifacts.append((package['name'], path, integrity))
if {name for name, _, _ in artifacts} != expected_names or len(artifacts) != len(expected_names):
    raise SystemExit('missing or duplicate npm packages')
for name, path, integrity in sorted(artifacts, key=lambda item: (item[0] == root_name, item[0])):
    found = subprocess.run(['npm', 'view', f'{name}@{version}', 'dist.integrity', '--json', '--registry', registry], capture_output=True, text=True)
    if found.returncode == 0:
        if json.loads(found.stdout) != integrity:
            raise SystemExit(f'{name}: existing version has different content')
        print(f'{name}@{version} is already published with matching content')
        continue
    if 'E404' not in found.stdout + found.stderr:
        raise SystemExit(f'{name}: unexpected registry lookup error: {found.stderr}')
    cmd = ['npm', 'publish', str(path), '--access', 'public', '--registry', registry]
    if kind == 'npm':
        cmd.append('--provenance')
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as err:
        print(f"\n[ERROR] Failed to publish {name}@{version} to {registry} (exit code {err.returncode}).", file=sys.stderr)
        if kind == 'npm':
            print("\n[npm Publication Troubleshooting]:", file=sys.stderr)
            print("1. If npm failed with 'EOTP' (This operation requires a one-time password):", file=sys.stderr)
            print("   - npm requires 2FA for your account. To publish non-interactively in CI:", file=sys.stderr)
            print("     a) Classic Token: create a token with type 'Automation' (Automation tokens bypass 2FA prompts in CI).", file=sys.stderr)
            print("     b) Granular Token: ensure 'Bypass 2FA' checkbox is explicitly checked.", file=sys.stderr)
            print("     c) Trusted Publishing (OIDC): once the package exists on npmjs.com, configure GitHub Actions as a Trusted Publisher and remove NODE_AUTH_TOKEN.", file=sys.stderr)
        raise
    print(f'Published {name}@{version} to {kind}')
