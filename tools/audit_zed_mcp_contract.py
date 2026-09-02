#!/usr/bin/env python3
"""Audit Rust dependency integrity and Zed-managed MCP consumer evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tomllib
from typing import Iterable, Iterator
from urllib.parse import urlparse

CONTRACT_SCHEMA = 'ores.mcp-rust-libs.consumer.v1'
PACKAGE_MANAGER_URL = 'https://github.com/zed-pkg'
DEFAULT_CONTRACT_PATH = '.zed-pkg/mcp-rust-libs.json'
EXCLUDED_DIRS = {'.git', 'target', 'vendor', 'node_modules', '.direnv', 'result'}
DEPENDENCY_TABLES = ('dependencies', 'dev-dependencies', 'build-dependencies')
EXACT_REVISION = re.compile(r'^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')
EXACT_VERSION = re.compile(r'^=\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
SHA256 = re.compile(r'^sha256:[0-9a-f]{64}$')
REPOSITORY = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
TRUE_VALUES = {'1', 'true', 'yes', 'on'}


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    message: str

    def render(self) -> str:
        where = f' [{self.path}]' if self.path else ''
        return f'{self.code}{where}: {self.message}'


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _manifest_paths(root: Path) -> list[Path]:
    manifests: list[Path] = []
    for path in root.rglob('Cargo.toml'):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        manifests.append(path)
    return sorted(manifests)


def _dependency_tables(document: dict) -> Iterator[dict]:
    for name in DEPENDENCY_TABLES:
        table = document.get(name)
        if isinstance(table, dict):
            yield table

    workspace = document.get('workspace')
    if isinstance(workspace, dict):
        table = workspace.get('dependencies')
        if isinstance(table, dict):
            yield table

    targets = document.get('target')
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for name in DEPENDENCY_TABLES:
                table = target.get(name)
                if isinstance(table, dict):
                    yield table


def _read_manifest(path: Path) -> dict:
    with path.open('rb') as handle:
        document = tomllib.load(handle)
    if not isinstance(document, dict):
        raise ValueError('manifest root must be a TOML table')
    return document


def _workspace_dependency_findings(root: Path, manifest: Path, document: dict) -> list[Finding]:
    findings: list[Finding] = []
    rel = manifest.relative_to(root).as_posix()
    for table in _dependency_tables(document):
        for dependency, spec in table.items():
            if not isinstance(spec, dict):
                continue
            sources = [key for key in ('git', 'path', 'registry') if key in spec]
            if len(sources) > 1:
                findings.append(Finding(
                    'MCP-DEP-001', rel,
                    f'dependency {dependency} declares mutually exclusive sources',
                ))

            git_url = spec.get('git')
            if git_url is not None:
                if not isinstance(git_url, str):
                    findings.append(Finding('MCP-DEP-002', rel, f'dependency {dependency} has a non-string git source'))
                    continue
                parsed = urlparse(git_url)
                if parsed.scheme != 'https' or not parsed.hostname:
                    findings.append(Finding('MCP-DEP-003', rel, f'dependency {dependency} must use a credential-free HTTPS git source'))
                if parsed.username or parsed.password:
                    findings.append(Finding('MCP-DEP-004', rel, f'dependency {dependency} embeds credentials in its git source'))
                if 'branch' in spec or 'tag' in spec:
                    findings.append(Finding('MCP-DEP-005', rel, f'dependency {dependency} must not use a floating branch or tag'))
                revision = spec.get('rev')
                if not isinstance(revision, str) or not EXACT_REVISION.fullmatch(revision):
                    findings.append(Finding('MCP-DEP-006', rel, f'dependency {dependency} must pin an exact 40- or 64-hex revision'))

            path_value = spec.get('path')
            if path_value is not None:
                if not isinstance(path_value, str) or not path_value.strip():
                    findings.append(Finding('MCP-DEP-007', rel, f'dependency {dependency} has an invalid path source'))
                    continue
                resolved = (manifest.parent / path_value).resolve()
                if not _inside(root, resolved):
                    findings.append(Finding('MCP-DEP-008', rel, f'dependency {dependency} escapes the audited repository root'))
                elif not resolved.exists():
                    findings.append(Finding('MCP-DEP-009', rel, f'dependency {dependency} points to a missing local path'))
    return findings


def _find_dependency(document: dict, package_name: str) -> tuple[str, object] | None:
    for table in _dependency_tables(document):
        for dependency, spec in table.items():
            actual_name = spec.get('package', dependency) if isinstance(spec, dict) else dependency
            if dependency == package_name or actual_name == package_name:
                return dependency, spec
    return None


def _load_contract(root: Path, rel_path: str) -> tuple[Path, dict]:
    rel = PurePosixPath(rel_path)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('contract path must remain inside the consumer repository')
    path = root / rel
    if path.is_symlink():
        raise ValueError('contract file must not be a symlink')
    with path.open('r', encoding='utf-8') as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError('contract root must be a JSON object')
    return path, document


def _contract_findings(root: Path, rel_path: str, required: bool) -> list[Finding]:
    path = root / PurePosixPath(rel_path)
    if not path.exists():
        return [Finding('MCP-ZED-001', rel_path, 'Zed MCP consumer contract is required')] if required else []

    try:
        contract_path, contract = _load_contract(root, rel_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return [Finding('MCP-ZED-002', rel_path, f'unable to load consumer contract: {error}')]

    findings: list[Finding] = []
    if contract.get('schema') != CONTRACT_SCHEMA:
        findings.append(Finding('MCP-ZED-003', rel_path, f'schema must be {CONTRACT_SCHEMA}'))
    if contract.get('package_manager') != PACKAGE_MANAGER_URL:
        findings.append(Finding('MCP-ZED-004', rel_path, f'package_manager must be {PACKAGE_MANAGER_URL}'))

    repository = contract.get('consumer_repository')
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        findings.append(Finding('MCP-ZED-005', rel_path, 'consumer_repository must be OWNER/REPO'))
    expected_repository = os.environ.get('GITHUB_REPOSITORY')
    if expected_repository and repository != expected_repository:
        findings.append(Finding('MCP-ZED-006', rel_path, 'consumer_repository does not match the checked-out GitHub repository'))

    lock_rel = contract.get('lockfile')
    lock_integrity = contract.get('lockfile_integrity')
    lock_path: Path | None = None
    lock_text = ''
    if not isinstance(lock_rel, str) or not lock_rel:
        findings.append(Finding('MCP-ZED-007', rel_path, 'lockfile path is required'))
    elif not isinstance(lock_integrity, str) or not SHA256.fullmatch(lock_integrity):
        findings.append(Finding('MCP-ZED-008', rel_path, 'lockfile_integrity must be lowercase sha256:<64 hex>'))
    else:
        lock_candidate = (root / PurePosixPath(lock_rel)).resolve()
        if not _inside(root, lock_candidate) or lock_candidate.is_symlink():
            findings.append(Finding('MCP-ZED-009', rel_path, 'lockfile must be a non-symlink inside the consumer repository'))
        elif not lock_candidate.is_file():
            findings.append(Finding('MCP-ZED-010', lock_rel, 'declared Zed lockfile does not exist'))
        else:
            data = lock_candidate.read_bytes()
            digest = f'sha256:{hashlib.sha256(data).hexdigest()}'
            if digest != lock_integrity:
                findings.append(Finding('MCP-ZED-011', lock_rel, 'declared lockfile integrity does not match file bytes'))
            if len(data) > 8_388_608 or b'\x00' in data:
                findings.append(Finding('MCP-ZED-012', lock_rel, 'lockfile must be bounded UTF-8 text'))
            else:
                try:
                    lock_text = data.decode('utf-8')
                    lock_path = lock_candidate
                except UnicodeDecodeError:
                    findings.append(Finding('MCP-ZED-012', lock_rel, 'lockfile must be bounded UTF-8 text'))

    packages = contract.get('packages')
    if not isinstance(packages, list) or not packages:
        findings.append(Finding('MCP-ZED-013', rel_path, 'packages must be a non-empty array'))
        return findings

    seen: set[tuple[str, str]] = set()
    for index, package in enumerate(packages, start=1):
        label = f'{rel_path}#packages[{index}]'
        if not isinstance(package, dict):
            findings.append(Finding('MCP-ZED-014', label, 'package entry must be an object'))
            continue
        name = package.get('name')
        version = package.get('version')
        manifest_rel = package.get('manifest')
        transport = package.get('transport')
        if not isinstance(name, str) or not name.strip():
            findings.append(Finding('MCP-ZED-015', label, 'package name is required'))
            continue
        if not isinstance(version, str) or not EXACT_VERSION.fullmatch(version):
            findings.append(Finding('MCP-ZED-016', label, 'package version must be exact Cargo syntax such as =1.2.3'))
        if not isinstance(manifest_rel, str) or not manifest_rel:
            findings.append(Finding('MCP-ZED-017', label, 'manifest path is required'))
            continue
        identity = (name, manifest_rel)
        if identity in seen:
            findings.append(Finding('MCP-ZED-018', label, 'duplicate package/manifest declaration'))
            continue
        seen.add(identity)

        manifest_path = (root / PurePosixPath(manifest_rel)).resolve()
        if not _inside(root, manifest_path) or manifest_path.is_symlink() or not manifest_path.is_file():
            findings.append(Finding('MCP-ZED-019', manifest_rel, 'manifest must be a regular file inside the consumer repository'))
            continue
        try:
            manifest = _read_manifest(manifest_path)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            findings.append(Finding('MCP-ZED-020', manifest_rel, f'unable to parse manifest: {error}'))
            continue
        located = _find_dependency(manifest, name)
        if located is None:
            findings.append(Finding('MCP-ZED-021', manifest_rel, f'package {name} is not declared as a dependency'))
            continue
        dependency, spec = located
        if not isinstance(spec, dict):
            findings.append(Finding('MCP-ZED-022', manifest_rel, f'dependency {dependency} must use an explicit table'))
            continue

        if transport == 'cargo-registry':
            registry = package.get('registry', 'zed-pkg')
            if spec.get('registry') != registry:
                findings.append(Finding('MCP-ZED-023', manifest_rel, f'dependency {dependency} must use registry {registry}'))
            if spec.get('version') != version:
                findings.append(Finding('MCP-ZED-024', manifest_rel, f'dependency {dependency} version must match the contract exactly'))
            if any(key in spec for key in ('git', 'branch', 'tag', 'rev', 'path')):
                findings.append(Finding('MCP-ZED-025', manifest_rel, f'dependency {dependency} bypasses the Zed registry transport'))
        elif transport == 'zed-vendor':
            path_value = spec.get('path')
            if not isinstance(path_value, str):
                findings.append(Finding('MCP-ZED-026', manifest_rel, f'dependency {dependency} must use a Zed vendor path'))
            else:
                resolved = (manifest_path.parent / path_value).resolve()
                vendor_root = (root / '.zed-pkg' / 'vendor').resolve()
                if not _inside(vendor_root, resolved):
                    findings.append(Finding('MCP-ZED-027', manifest_rel, f'dependency {dependency} must resolve under .zed-pkg/vendor'))
            if spec.get('version') != version:
                findings.append(Finding('MCP-ZED-028', manifest_rel, f'dependency {dependency} version must match the contract exactly'))
            if any(key in spec for key in ('git', 'branch', 'tag', 'rev', 'registry')):
                findings.append(Finding('MCP-ZED-029', manifest_rel, f'dependency {dependency} mixes vendor and remote transports'))
        elif transport == 'git-mirror':
            git_url = spec.get('git')
            revision = spec.get('rev')
            parsed = urlparse(git_url) if isinstance(git_url, str) else None
            if not parsed or parsed.scheme != 'https' or parsed.hostname != 'github.com' or not parsed.path.startswith('/zed-pkg/'):
                findings.append(Finding('MCP-ZED-030', manifest_rel, f'dependency {dependency} must use an HTTPS github.com/zed-pkg mirror'))
            if not isinstance(revision, str) or not EXACT_REVISION.fullmatch(revision):
                findings.append(Finding('MCP-ZED-031', manifest_rel, f'dependency {dependency} must pin the mirror by exact revision'))
            if 'branch' in spec or 'tag' in spec or 'path' in spec or 'registry' in spec:
                findings.append(Finding('MCP-ZED-032', manifest_rel, f'dependency {dependency} mixes or floats transport selectors'))
        else:
            findings.append(Finding('MCP-ZED-033', label, 'transport must be cargo-registry, zed-vendor, or git-mirror'))

        if lock_path and isinstance(version, str):
            plain_version = version.removeprefix('=')
            if name not in lock_text or plain_version not in lock_text:
                findings.append(Finding('MCP-ZED-034', contract.get('lockfile', ''), f'lockfile must contain package {name} and version {plain_version}'))

    return findings


def audit(root: Path, *, require_contract: bool = False, contract_path: str = DEFAULT_CONTRACT_PATH) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for manifest in _manifest_paths(root):
        rel = manifest.relative_to(root).as_posix()
        try:
            document = _read_manifest(manifest)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            findings.append(Finding('MCP-MANIFEST-001', rel, f'unable to parse Cargo manifest: {error}'))
            continue
        findings.extend(_workspace_dependency_findings(root, manifest, document))
    findings.extend(_contract_findings(root, contract_path, require_contract))
    return sorted(set(findings))


def main() -> int:
    root = Path(os.environ.get('MCP_CONSUMER_ROOT', Path(__file__).resolve().parents[1]))
    required = os.environ.get('MCP_REQUIRE_ZED_CONTRACT', '').strip().lower() in TRUE_VALUES
    contract_path = os.environ.get('MCP_ZED_CONTRACT_PATH', DEFAULT_CONTRACT_PATH)
    findings = audit(root, require_contract=required, contract_path=contract_path)
    if findings:
        print(f'MCP dependency audit failed with {len(findings)} finding(s):', file=sys.stderr)
        for finding in findings:
            print(f'- {finding.render()}', file=sys.stderr)
        return 1
    print('MCP dependency audit passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
