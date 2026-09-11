from __future__ import annotations

from datetime import date
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / 'tools' / 'audit_mcp_fleet.py'
SPEC = importlib.util.spec_from_file_location('audit_mcp_fleet', MODULE_PATH)
assert SPEC and SPEC.loader
FLEET = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FLEET
SPEC.loader.exec_module(FLEET)

TODAY = date(2026, 9, 1)


class FleetWorkspace:
    def __init__(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.checkouts = self.root / 'checkouts'
        self.checkouts.mkdir()
        self.inventory_path = self.root / 'inventory.json'

    def close(self) -> None:
        self._temp.cleanup()

    def write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def checkout(self, repository: str, *, contract_repository: str | None = None) -> Path:
        checkout = self.checkouts.joinpath(*repository.split('/'))
        checkout.mkdir(parents=True)
        self.write(checkout / 'Cargo.toml', '''
[package]
name = "example-mcp-server"
version = "0.1.0"

[dependencies]
mcp-core = { version = "=1.2.3", registry = "zed-pkg" }
''')
        lock = self.write(checkout / '.zed-pkg/zed.lock', 'mcp-core 1.2.3\n')
        digest = f"sha256:{hashlib.sha256(lock.read_bytes()).hexdigest()}"
        contract = {
            'schema': 'ores.mcp-rust-libs.consumer.v1',
            'package_manager': 'https://github.com/zed-pkg',
            'consumer_repository': contract_repository or repository,
            'lockfile': '.zed-pkg/zed.lock',
            'lockfile_integrity': digest,
            'packages': [{
                'name': 'mcp-core',
                'version': '=1.2.3',
                'manifest': 'Cargo.toml',
                'transport': 'cargo-registry',
                'registry': 'zed-pkg',
            }],
        }
        self.write(
            checkout / '.zed-pkg/mcp-rust-libs.json',
            json.dumps(contract, indent=2) + '\n',
        )
        return checkout

    def entry(self, repository: str, *, status: str = 'adopted', **extra) -> dict:
        entry = {
            'repository': repository,
            'checkout': repository,
            'classification': 'mcp-server',
            'status': status,
            'expected_packages': ['mcp-core'],
        }
        entry.update(extra)
        return entry

    def save(self, entries: list[dict]) -> None:
        document = {
            'schema': FLEET.FLEET_SCHEMA,
            'generated_at': '2026-09-01T12:00:00Z',
            'repositories': entries,
        }
        self.write(self.inventory_path, json.dumps(document, indent=2) + '\n')

    def findings(
        self,
        *,
        require_adopted: bool = True,
        require_complete_inventory: bool = True,
    ):
        return FLEET.audit(
            self.inventory_path,
            self.checkouts,
            require_adopted=require_adopted,
            require_complete_inventory=require_complete_inventory,
            today=TODAY,
        )[0]

    def codes(self, **kwargs) -> set[str]:
        return {finding.code for finding in self.findings(**kwargs)}


class McpFleetAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = FleetWorkspace()
        self.addCleanup(self.workspace.close)

    def test_adopted_consumer_with_exact_zed_evidence_passes(self) -> None:
        repository = 'example-org/example-mcp-server'
        self.workspace.checkout(repository)
        self.workspace.save([self.workspace.entry(repository)])
        findings, counts = FLEET.audit(
            self.workspace.inventory_path,
            self.workspace.checkouts,
            today=TODAY,
        )
        self.assertEqual(findings, [])
        self.assertEqual(counts, {'adopted': 1, 'pending': 0, 'waived': 0})

    def test_discovered_mcp_checkout_cannot_be_omitted_from_inventory(self) -> None:
        listed = 'example-org/listed-mcp-server'
        omitted = 'example-org/omitted-mcp-server'
        self.workspace.checkout(listed)
        self.workspace.checkout(omitted)
        self.workspace.save([self.workspace.entry(listed)])
        findings = self.workspace.findings()
        self.assertTrue(any(
            finding.code == 'MCP-FLEET-018' and finding.repository == omitted
            for finding in findings
        ))

    def test_pending_consumer_fails_release_mode_but_can_be_reported(self) -> None:
        repository = 'example-org/pending-mcp-server'
        self.workspace.checkout(repository)
        self.workspace.save([
            self.workspace.entry(repository, status='pending', tracking='DEN-612')
        ])
        self.assertIn('MCP-FLEET-016', self.workspace.codes())
        self.assertNotIn(
            'MCP-FLEET-016',
            self.workspace.codes(require_adopted=False),
        )

    def test_expired_waiver_fails_closed(self) -> None:
        repository = 'example-org/waived-mcp-server'
        self.workspace.checkout(repository)
        self.workspace.save([
            self.workspace.entry(
                repository,
                status='waived',
                tracking='DEN-612',
                waiver_reason='Migration is blocked on an upstream protocol release.',
                waiver_expires='2026-08-31',
            )
        ])
        self.assertIn('MCP-FLEET-023', self.workspace.codes())

    def test_waiver_cannot_exceed_ninety_days(self) -> None:
        repository = 'example-org/long-waiver-mcp-server'
        self.workspace.checkout(repository)
        self.workspace.save([
            self.workspace.entry(
                repository,
                status='waived',
                tracking='DEN-612',
                waiver_reason='Temporary compatibility boundary.',
                waiver_expires='2026-12-15',
            )
        ])
        self.assertIn('MCP-FLEET-024', self.workspace.codes())

    def test_expected_package_must_be_declared_in_zed_evidence(self) -> None:
        repository = 'example-org/package-mismatch-mcp-server'
        self.workspace.checkout(repository)
        entry = self.workspace.entry(repository)
        entry['expected_packages'] = ['mcp-core', 'mcp-transport']
        self.workspace.save([entry])
        self.assertIn('MCP-FLEET-017', self.workspace.codes())

    def test_contract_repository_must_match_inventory_identity(self) -> None:
        repository = 'example-org/repository-mismatch-mcp-server'
        self.workspace.checkout(repository, contract_repository='different-org/different-mcp-server')
        self.workspace.save([self.workspace.entry(repository)])
        codes = self.workspace.codes()
        self.assertIn('MCP-CONSUMER-MCP-ZED-006', codes)

    def test_symlinked_checkout_is_rejected(self) -> None:
        repository = 'example-org/symlinked-mcp-server'
        actual = self.workspace.root / 'actual-mcp-server'
        actual.mkdir()
        self.workspace.write(actual / 'Cargo.toml', '[package]\nname="mcp"\nversion="0.1.0"\n')
        owner = self.workspace.checkouts / 'example-org'
        owner.mkdir()
        os.symlink(actual, owner / 'symlinked-mcp-server')
        self.workspace.save([self.workspace.entry(repository)])
        self.assertIn('MCP-FLEET-011', self.workspace.codes())

    def test_checkout_path_must_match_owner_and_repository(self) -> None:
        repository = 'example-org/path-mcp-server'
        self.workspace.checkout(repository)
        entry = self.workspace.entry(repository)
        entry['checkout'] = '../escape'
        self.workspace.save([entry])
        self.assertIn('MCP-FLEET-011', self.workspace.codes())

    def test_floating_git_dependency_is_reported_through_fleet_audit(self) -> None:
        repository = 'example-org/floating-mcp-server'
        checkout = self.workspace.checkout(repository)
        self.workspace.write(checkout / 'Cargo.toml', '''
[package]
name = "floating-mcp-server"
version = "0.1.0"

[dependencies]
mcp-core = { git = "https://github.com/zed-pkg/mcp-core", branch = "main" }
''')
        self.workspace.save([self.workspace.entry(repository)])
        codes = self.workspace.codes()
        self.assertIn('MCP-CONSUMER-MCP-DEP-005', codes)
        self.assertIn('MCP-CONSUMER-MCP-DEP-006', codes)


if __name__ == '__main__':
    unittest.main()
