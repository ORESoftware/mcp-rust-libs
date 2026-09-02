from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / 'tools' / 'audit_zed_mcp_contract.py'
SPEC = importlib.util.spec_from_file_location('audit_zed_mcp_contract', MODULE_PATH)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class ConsumerRepo:
    def __init__(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)

    def close(self) -> None:
        self._temp.cleanup()

    def write(self, path: str, content: str) -> Path:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding='utf-8')
        return destination

    def write_contract(self, package: dict, lock_text: str = 'mcp-core 1.2.3\n') -> None:
        lock = self.write('.zed-pkg/zed.lock', lock_text)
        integrity = f"sha256:{hashlib.sha256(lock.read_bytes()).hexdigest()}"
        contract = {
            'schema': AUDIT.CONTRACT_SCHEMA,
            'package_manager': AUDIT.PACKAGE_MANAGER_URL,
            'consumer_repository': 'example/mcp-server',
            'lockfile': '.zed-pkg/zed.lock',
            'lockfile_integrity': integrity,
            'packages': [package],
        }
        self.write(AUDIT.DEFAULT_CONTRACT_PATH, json.dumps(contract, indent=2) + '\n')


class ZedMcpContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ConsumerRepo()
        self.addCleanup(self.repo.close)

    def codes(self, *, required: bool = True) -> set[str]:
        return {finding.code for finding in AUDIT.audit(self.repo.root, require_contract=required)}

    def test_exact_zed_cargo_registry_dependency_passes(self) -> None:
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = { version = "=1.2.3", registry = "zed-pkg" }
''')
        self.repo.write_contract({
            'name': 'mcp-core',
            'version': '=1.2.3',
            'manifest': 'Cargo.toml',
            'transport': 'cargo-registry',
            'registry': 'zed-pkg',
        })
        self.assertEqual(AUDIT.audit(self.repo.root, require_contract=True), [])

    def test_floating_git_dependency_is_rejected(self) -> None:
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = { git = "https://github.com/zed-pkg/mcp-core", branch = "main" }
''')
        codes = self.codes(required=False)
        self.assertIn('MCP-DEP-005', codes)
        self.assertIn('MCP-DEP-006', codes)

    def test_exact_zed_git_mirror_dependency_passes(self) -> None:
        revision = 'a' * 40
        self.repo.write('Cargo.toml', f'''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = {{ git = "https://github.com/zed-pkg/mcp-core", rev = "{revision}", version = "=1.2.3" }}
''')
        self.repo.write_contract({
            'name': 'mcp-core',
            'version': '=1.2.3',
            'manifest': 'Cargo.toml',
            'transport': 'git-mirror',
        })
        self.assertEqual(AUDIT.audit(self.repo.root, require_contract=True), [])

    def test_path_dependency_must_not_escape_consumer_root(self) -> None:
        outside = self.repo.root.parent / 'outside-mcp-lib'
        outside.mkdir(exist_ok=True)
        self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
        self.repo.write('Cargo.toml', f'''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = {{ path = "{outside.as_posix()}" }}
''')
        self.assertIn('MCP-DEP-008', self.codes(required=False))

    def test_zed_vendor_dependency_must_remain_under_managed_vendor_root(self) -> None:
        self.repo.write('.zed-pkg/vendor/mcp-core/Cargo.toml', '''
[package]
name = "mcp-core"
version = "1.2.3"
''')
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = { path = ".zed-pkg/vendor/mcp-core", version = "=1.2.3" }
''')
        self.repo.write_contract({
            'name': 'mcp-core',
            'version': '=1.2.3',
            'manifest': 'Cargo.toml',
            'transport': 'zed-vendor',
        })
        self.assertEqual(AUDIT.audit(self.repo.root, require_contract=True), [])

    def test_lockfile_integrity_tampering_is_rejected(self) -> None:
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = { version = "=1.2.3", registry = "zed-pkg" }
''')
        self.repo.write_contract({
            'name': 'mcp-core',
            'version': '=1.2.3',
            'manifest': 'Cargo.toml',
            'transport': 'cargo-registry',
        })
        self.repo.write('.zed-pkg/zed.lock', 'mcp-core 9.9.9\n')
        self.assertIn('MCP-ZED-011', self.codes())

    def test_required_contract_cannot_be_omitted(self) -> None:
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"
''')
        self.assertIn('MCP-ZED-001', self.codes())

    def test_contract_repository_must_match_ci_checkout(self) -> None:
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = { version = "=1.2.3", registry = "zed-pkg" }
''')
        self.repo.write_contract({
            'name': 'mcp-core',
            'version': '=1.2.3',
            'manifest': 'Cargo.toml',
            'transport': 'cargo-registry',
        })
        previous = os.environ.get('GITHUB_REPOSITORY')
        os.environ['GITHUB_REPOSITORY'] = 'different/repository'
        self.addCleanup(
            lambda: os.environ.__setitem__('GITHUB_REPOSITORY', previous)
            if previous is not None
            else os.environ.pop('GITHUB_REPOSITORY', None)
        )
        self.assertIn('MCP-ZED-006', self.codes())

    def test_symlinked_lockfile_is_rejected(self) -> None:
        self.repo.write('Cargo.toml', '''
[package]
name = "consumer"
version = "0.1.0"

[dependencies]
mcp-core = { version = "=1.2.3", registry = "zed-pkg" }
''')
        target = self.repo.write('real.lock', 'mcp-core 1.2.3\n')
        lock = self.repo.root / '.zed-pkg/zed.lock'
        lock.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, lock)
        integrity = f"sha256:{hashlib.sha256(target.read_bytes()).hexdigest()}"
        contract = {
            'schema': AUDIT.CONTRACT_SCHEMA,
            'package_manager': AUDIT.PACKAGE_MANAGER_URL,
            'consumer_repository': 'example/mcp-server',
            'lockfile': '.zed-pkg/zed.lock',
            'lockfile_integrity': integrity,
            'packages': [{
                'name': 'mcp-core',
                'version': '=1.2.3',
                'manifest': 'Cargo.toml',
                'transport': 'cargo-registry',
            }],
        }
        self.repo.write(AUDIT.DEFAULT_CONTRACT_PATH, json.dumps(contract))
        self.assertIn('MCP-ZED-009', self.codes())


if __name__ == '__main__':
    unittest.main()
