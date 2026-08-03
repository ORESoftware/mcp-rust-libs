from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("check_deployable_lockfile.py")
SPEC = importlib.util.spec_from_file_location("lockcheck", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class DeployableLockfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write(
            "Cargo.toml",
            "[package]\nname='server'\nversion='0.1.0'\nedition='2024'\n",
        )
        self.write("src/main.rs", "fn main() {}\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, path: str, content: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def add(self, *paths: str) -> None:
        subprocess.run(["git", "-C", str(self.root), "add", *paths], check=True)

    def valid_lock(self) -> None:
        self.write(
            "Cargo.lock",
            "version = 4\n\n[[package]]\nname = 'server'\nversion = '0.1.0'\n",
        )

    def test_missing_lockfile_fails(self) -> None:
        result = module.check(self.root)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "missing-lockfile")

    def test_ignored_lockfile_fails_even_when_present(self) -> None:
        self.valid_lock()
        self.write(".gitignore", "Cargo.lock\n")
        result = module.check(self.root)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "ignored-lockfile")

    def test_untracked_lockfile_fails(self) -> None:
        self.valid_lock()
        result = module.check(self.root)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "untracked-lockfile")

    def test_invalid_or_empty_lockfile_fails(self) -> None:
        self.write("Cargo.lock", "not = [valid\n")
        self.add("Cargo.lock")
        result = module.check(self.root)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "invalid-lockfile")

        self.write("Cargo.lock", "version = 4\n")
        self.add("Cargo.lock")
        result = module.check(self.root)
        self.assertFalse(result.ok)
        self.assertEqual(result.code, "empty-lockfile")

    def test_tracked_valid_lockfile_passes(self) -> None:
        self.valid_lock()
        self.add("Cargo.lock")
        result = module.check(self.root)
        self.assertTrue(result.ok)
        self.assertEqual(result.code, "tracked-lockfile")

    def test_library_only_workspace_is_not_forced_into_application_policy(self) -> None:
        (self.root / "src/main.rs").unlink()
        self.write("src/lib.rs", "pub fn library() {}\n")
        result = module.check(self.root)
        self.assertTrue(result.ok)
        self.assertEqual(result.code, "not-deployable")


if __name__ == "__main__":
    unittest.main()
