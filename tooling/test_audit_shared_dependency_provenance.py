from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("audit_shared_dependency_provenance.py")
SPEC = importlib.util.spec_from_file_location("dependency_provenance", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)

REVISION_A = "0123456789abcdef0123456789abcdef01234567"
REVISION_B = "89abcdef0123456789abcdef0123456789abcdef"


class DependencyProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write(
            "Cargo.toml",
            f'''[package]
name = "consumer"
version = "0.1.0"

[dependencies]
ore-mcp-org-server = {{ git = "https://github.com/ORESoftware/mcp-rust-libs", rev = "{REVISION_A}" }}
''',
        )
        self.write(
            ".zpkg.toml",
            '''[package]
org = "example"
name = "consumer"
version = "0.1.0"

[dependencies]
"oresoftware/mcp-rust-libs" = "^0.1.0"

[build]
command = "cargo build --release --locked"
''',
        )
        self.write(
            ".zpkg.lock",
            '''version = 1

[[packages]]
name = "oresoftware/mcp-rust-libs"
version = "0.1.0"
''',
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def audit(self, **kwargs):
        return module.audit(self.root, **kwargs)

    def codes(self, **kwargs) -> set[str]:
        return {finding.code for finding in self.audit(**kwargs)}

    def test_exact_cargo_and_zed_provenance_passes(self) -> None:
        findings = self.audit(
            require_zed_lock=True,
            verify_reachability=True,
            compare_status=lambda _: "ahead",
        )
        self.assertFalse(any(item.severity in {"medium", "high"} for item in findings), findings)
        self.assertIn("shared-mcp-runtime-declared", {item.code for item in findings})

    def test_missing_shared_runtime_is_high(self) -> None:
        self.write(
            "Cargo.toml",
            '''[package]
name = "consumer"
version = "0.1.0"
[dependencies]
rmcp = "2.2.0"
''',
        )
        self.assertIn("missing-shared-mcp-runtime", self.codes())

    def test_branch_and_short_revision_are_rejected(self) -> None:
        self.write(
            "Cargo.toml",
            '''[package]
name = "consumer"
version = "0.1.0"
[dependencies]
ore-mcp-bootstrap = { git = "https://github.com/ORESoftware/mcp-rust-libs", branch = "main", rev = "deadbeef" }
''',
        )
        codes = self.codes()
        self.assertIn("mutable-or-local-shared-mcp-source", codes)
        self.assertIn("invalid-shared-mcp-revision", codes)

    def test_wrong_repository_is_rejected(self) -> None:
        self.write(
            "Cargo.toml",
            f'''[package]
name = "consumer"
version = "0.1.0"
[dependencies]
ore-mcp-bootstrap = {{ git = "https://example.invalid/mcp-rust-libs", rev = "{REVISION_A}" }}
''',
        )
        self.assertIn("wrong-shared-mcp-repository", self.codes())

    def test_shared_crates_must_use_one_revision(self) -> None:
        self.write(
            "Cargo.toml",
            f'''[package]
name = "consumer"
version = "0.1.0"
[dependencies]
ore-mcp-bootstrap = {{ git = "https://github.com/ORESoftware/mcp-rust-libs.git", rev = "{REVISION_A}" }}
ore-mcp-safety = {{ git = "https://github.com/ORESoftware/mcp-rust-libs", rev = "{REVISION_B}" }}
''',
        )
        self.assertIn("split-shared-mcp-revision", self.codes())

    def test_zed_manifest_must_declare_canonical_edge_and_locked_build(self) -> None:
        self.write(
            ".zpkg.toml",
            '''[package]
org = "example"
name = "consumer"
version = "0.1.0"
[dependencies]
"somewhere/else" = "^0.1.0"
[build]
command = "cargo build --release"
''',
        )
        codes = self.codes()
        self.assertIn("missing-zed-shared-mcp-edge", codes)
        self.assertIn("unlocked-zed-cargo-build", codes)

    def test_manifest_only_zed_edge_is_reported_without_false_frozen_claim(self) -> None:
        (self.root / ".zpkg.lock").unlink()
        findings = self.audit(require_zed_lock=False)
        missing = [item for item in findings if item.code == "missing-zed-lock"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].severity, "medium")
        self.assertIn("manifest-only", missing[0].message)

    def test_metadata_only_lock_is_not_frozen_resolution(self) -> None:
        self.write(".zpkg.lock", "version = 1\n")
        findings = self.audit(require_zed_lock=False)
        placeholder = [item for item in findings if item.code == "empty-zed-lock"]
        self.assertEqual(len(placeholder), 1)
        self.assertEqual(placeholder[0].severity, "medium")
        self.assertIn("placeholder", placeholder[0].message)

    def test_frozen_gate_requires_regular_zed_lock(self) -> None:
        (self.root / ".zpkg.lock").unlink()
        findings = self.audit(require_zed_lock=True)
        missing = [item for item in findings if item.code == "missing-zed-lock"]
        self.assertEqual(missing[0].severity, "high")

    def test_frozen_gate_rejects_metadata_only_lock(self) -> None:
        self.write(".zpkg.lock", "schemaVersion = 1\n")
        findings = self.audit(require_zed_lock=True)
        placeholder = [item for item in findings if item.code == "empty-zed-lock"]
        self.assertEqual(placeholder[0].severity, "high")

    def test_diverged_revision_is_rejected(self) -> None:
        findings = self.audit(
            verify_reachability=True,
            compare_status=lambda _: "diverged",
        )
        self.assertIn("unmerged-shared-mcp-revision", {item.code for item in findings})

    def test_unavailable_reachability_is_honest_medium_state(self) -> None:
        def unavailable(_: str) -> str:
            raise TimeoutError("offline")

        findings = self.audit(verify_reachability=True, compare_status=unavailable)
        item = next(item for item in findings if item.code == "shared-mcp-reachability-unverified")
        self.assertEqual(item.severity, "medium")

    def test_symlinked_zed_lock_is_rejected(self) -> None:
        (self.root / ".zpkg.lock").unlink()
        (self.root / "target.lock").write_text("lock\n", encoding="utf-8")
        (self.root / ".zpkg.lock").symlink_to(self.root / "target.lock")
        self.assertIn("invalid-zed-lock", self.codes())


if __name__ == "__main__":
    unittest.main()
