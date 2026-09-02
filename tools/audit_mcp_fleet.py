#!/usr/bin/env python3
"""Audit a checked-out MCP server fleet for Zed-managed mcp-rust-libs adoption.

The tool is intentionally offline. A privileged inventory job may clone or
materialize repositories into a workspace, but this audit neither requests nor
reads a GitHub token. Diagnostics contain repository names and policy codes,
never dependency URLs with credentials, lockfile bodies, or secret values.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable

TOOLS_DIR = Path(__file__).resolve().parent
CONSUMER_AUDIT_PATH = TOOLS_DIR / 'audit_zed_mcp_contract.py'
SPEC = importlib.util.spec_from_file_location('audit_zed_mcp_contract', CONSUMER_AUDIT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f'unable to load {CONSUMER_AUDIT_PATH}')
CONSUMER_AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, CONSUMER_AUDIT)
SPEC.loader.exec_module(CONSUMER_AUDIT)

FLEET_SCHEMA = 'ores.mcp-rust-libs.fleet.v1'
MAX_INVENTORY_BYTES = 2_097_152
MAX_REPOSITORIES = 10_000
MAX_WAIVER_DAYS = 90
REPOSITORY = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
LINEAR_ISSUE = re.compile(r'^DEN-[1-9][0-9]*$')
MCP_SIGNAL = re.compile(
    r'(?i)(?:\bmcp\b|mcp[-_]|[-_]mcp|rmcp|modelcontextprotocol|mcp-rust-libs)'
)
EXCLUDED_PARTS = frozenset({
    '.git', '.direnv', 'node_modules', 'target', 'vendor', '.terraform',
    'result', 'dist', 'build',
})


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    repository: str
    message: str

    def render(self) -> str:
        where = f' [{self.repository}]' if self.repository else ''
        return f'{self.code}{where}: {self.message}'


@contextmanager
def expected_repository(repository: str):
    previous = os.environ.get('GITHUB_REPOSITORY')
    os.environ['GITHUB_REPOSITORY'] = repository
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop('GITHUB_REPOSITORY', None)
        else:
            os.environ['GITHUB_REPOSITORY'] = previous


def _safe_relative(value: object) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or '.' in path.parts:
        return None
    return path


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _bounded_json(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError('inventory must not be a symlink')
    if not path.is_file():
        raise ValueError('inventory does not exist as a regular file')
    if path.stat().st_size > MAX_INVENTORY_BYTES:
        raise ValueError(f'inventory exceeds {MAX_INVENTORY_BYTES} bytes')
    with path.open('r', encoding='utf-8') as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError('inventory root must be a JSON object')
    return document


def _repository_checkout(root: Path, repository: str, checkout_value: object) -> tuple[Path | None, str | None]:
    rel = _safe_relative(checkout_value)
    if rel is None:
        return None, 'checkout must be a safe repository-relative path'
    expected = PurePosixPath(*repository.split('/'))
    if rel != expected:
        return None, f'checkout must be {expected.as_posix()} for deterministic fleet layout'

    source = root.joinpath(*rel.parts)
    cursor = root
    for part in rel.parts:
        cursor /= part
        if cursor.is_symlink():
            return None, 'checkout path must not traverse a symlink'
    resolved = source.resolve(strict=False)
    if not _inside(root, resolved):
        return None, 'checkout escapes the fleet root'
    if not resolved.is_dir():
        return None, 'checkout directory is missing'
    return resolved, None


def _load_contract_packages(checkout: Path) -> set[str]:
    path = checkout / CONSUMER_AUDIT.DEFAULT_CONTRACT_PATH
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        return set()
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return set()
    packages = document.get('packages') if isinstance(document, dict) else None
    if not isinstance(packages, list):
        return set()
    return {
        item['name']
        for item in packages
        if isinstance(item, dict) and isinstance(item.get('name'), str) and item['name']
    }


def _is_mcp_checkout(path: Path) -> bool:
    if MCP_SIGNAL.search(path.name):
        return True
    manifests = sorted(path.rglob('Cargo.toml'))
    for manifest in manifests:
        try:
            rel = manifest.relative_to(path)
        except ValueError:
            continue
        if any(part in EXCLUDED_PARTS for part in rel.parts):
            continue
        if manifest.is_symlink() or manifest.stat().st_size > 2_097_152:
            continue
        try:
            text = manifest.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        if MCP_SIGNAL.search(text):
            return True
    return False


def discover_checkouts(root: Path) -> set[str]:
    repositories: set[str] = set()
    if not root.is_dir() or root.is_symlink():
        return repositories
    for owner in sorted(root.iterdir()):
        if owner.is_symlink() or not owner.is_dir() or owner.name.startswith('.'):
            continue
        for repository in sorted(owner.iterdir()):
            if repository.is_symlink() or not repository.is_dir() or repository.name.startswith('.'):
                continue
            identity = f'{owner.name}/{repository.name}'
            if REPOSITORY.fullmatch(identity) and _is_mcp_checkout(repository):
                repositories.add(identity)
    return repositories


def _parse_day(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _audit_waiver(repository: str, entry: dict[str, Any], today: date) -> list[Finding]:
    findings: list[Finding] = []
    reason = entry.get('waiver_reason')
    tracking = entry.get('tracking')
    expires = _parse_day(entry.get('waiver_expires'))
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        findings.append(Finding('MCP-FLEET-020', repository, 'waiver requires a bounded non-empty reason'))
    if not isinstance(tracking, str) or not LINEAR_ISSUE.fullmatch(tracking):
        findings.append(Finding('MCP-FLEET-021', repository, 'waiver requires a Linear issue identifier'))
    if expires is None:
        findings.append(Finding('MCP-FLEET-022', repository, 'waiver_expires must be an ISO date'))
    else:
        if expires < today:
            findings.append(Finding('MCP-FLEET-023', repository, 'waiver has expired'))
        if (expires - today).days > MAX_WAIVER_DAYS:
            findings.append(Finding('MCP-FLEET-024', repository, f'waiver exceeds the {MAX_WAIVER_DAYS}-day maximum'))
    return findings


def audit(
    inventory_path: Path,
    checkout_root: Path,
    *,
    require_adopted: bool = True,
    require_complete_inventory: bool = True,
    today: date | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    today = today or datetime.now(timezone.utc).date()
    root = checkout_root.resolve()
    findings: list[Finding] = []
    counts = {'adopted': 0, 'pending': 0, 'waived': 0}

    try:
        inventory = _bounded_json(inventory_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return [Finding('MCP-FLEET-001', '', f'unable to load inventory: {error}')], counts

    if inventory.get('schema') != FLEET_SCHEMA:
        findings.append(Finding('MCP-FLEET-002', '', f'schema must be {FLEET_SCHEMA}'))
    generated_at = inventory.get('generated_at')
    if not isinstance(generated_at, str):
        findings.append(Finding('MCP-FLEET-003', '', 'generated_at must be an ISO date-time'))
    else:
        try:
            datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
        except ValueError:
            findings.append(Finding('MCP-FLEET-003', '', 'generated_at must be an ISO date-time'))

    entries = inventory.get('repositories')
    if not isinstance(entries, list):
        findings.append(Finding('MCP-FLEET-004', '', 'repositories must be an array'))
        return sorted(set(findings)), counts
    if len(entries) > MAX_REPOSITORIES:
        findings.append(Finding('MCP-FLEET-005', '', f'inventory exceeds {MAX_REPOSITORIES} repositories'))
        return sorted(set(findings)), counts

    listed: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        label = f'entry-{index}'
        if not isinstance(entry, dict):
            findings.append(Finding('MCP-FLEET-006', label, 'repository entry must be an object'))
            continue
        repository = entry.get('repository')
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
            findings.append(Finding('MCP-FLEET-007', label, 'repository must be OWNER/REPO'))
            continue
        if repository in listed:
            findings.append(Finding('MCP-FLEET-008', repository, 'repository is duplicated in inventory'))
            continue
        listed.add(repository)

        classification = entry.get('classification')
        if classification not in {'mcp-server', 'mcp-library', 'mcp-gateway', 'mcp-test'}:
            findings.append(Finding('MCP-FLEET-009', repository, 'classification is invalid'))
        status = entry.get('status')
        if status not in counts:
            findings.append(Finding('MCP-FLEET-010', repository, 'status must be adopted, pending, or waived'))
            continue
        counts[status] += 1

        checkout, checkout_error = _repository_checkout(root, repository, entry.get('checkout'))
        if checkout_error:
            findings.append(Finding('MCP-FLEET-011', repository, checkout_error))
            continue
        assert checkout is not None

        if not _is_mcp_checkout(checkout):
            findings.append(Finding('MCP-FLEET-012', repository, 'checkout contains no MCP repository signal'))

        expected_packages = entry.get('expected_packages')
        if not isinstance(expected_packages, list) or not expected_packages:
            findings.append(Finding('MCP-FLEET-013', repository, 'expected_packages must be a non-empty array'))
            expected_packages = []
        elif (
            any(not isinstance(package, str) or not package for package in expected_packages)
            or len(expected_packages) != len(set(expected_packages))
        ):
            findings.append(Finding('MCP-FLEET-014', repository, 'expected_packages must contain unique non-empty strings'))

        if status == 'waived':
            findings.extend(_audit_waiver(repository, entry, today))
            continue
        if status == 'pending':
            tracking = entry.get('tracking')
            if not isinstance(tracking, str) or not LINEAR_ISSUE.fullmatch(tracking):
                findings.append(Finding('MCP-FLEET-015', repository, 'pending adoption requires a Linear issue identifier'))
            if require_adopted:
                findings.append(Finding('MCP-FLEET-016', repository, 'consumer adoption is still pending'))
            continue

        with expected_repository(repository):
            consumer_findings = CONSUMER_AUDIT.audit(checkout, require_contract=True)
        for consumer_finding in consumer_findings:
            findings.append(Finding(
                f'MCP-CONSUMER-{consumer_finding.code}',
                repository,
                f'{consumer_finding.path}: {consumer_finding.message}',
            ))

        declared_packages = _load_contract_packages(checkout)
        missing_packages = sorted(set(expected_packages) - declared_packages)
        for package in missing_packages:
            findings.append(Finding('MCP-FLEET-017', repository, f'expected package {package} is absent from Zed evidence'))

    if require_complete_inventory:
        for repository in sorted(discover_checkouts(root) - listed):
            findings.append(Finding('MCP-FLEET-018', repository, 'MCP checkout is missing from fleet inventory'))

    return sorted(set(findings)), counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path, help='Path to fleet inventory JSON')
    parser.add_argument('--checkout-root', required=True, type=Path, help='Root containing OWNER/REPO checkouts')
    parser.add_argument(
        '--allow-pending',
        action='store_true',
        help='Report pending entries but do not fail merely because they are pending',
    )
    parser.add_argument(
        '--allow-unlisted',
        action='store_true',
        help='Do not fail when a discovered MCP checkout is absent from the inventory',
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    findings, counts = audit(
        args.inventory,
        args.checkout_root,
        require_adopted=not args.allow_pending,
        require_complete_inventory=not args.allow_unlisted,
    )
    if findings:
        print(f'MCP fleet audit failed with {len(findings)} finding(s):', file=sys.stderr)
        for finding in findings:
            print(f'- {finding.render()}', file=sys.stderr)
        return 1
    rendered = ', '.join(f'{status}={counts[status]}' for status in sorted(counts))
    print(f'MCP fleet audit passed ({rendered})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
