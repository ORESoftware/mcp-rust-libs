from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("audit_rust_mcp_server.py")
SPEC = importlib.util.spec_from_file_location("mcp_audit", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def codes(self) -> set[str]:
        return {finding.code for finding in module.audit(self.root)}

    def test_flags_handwritten_stale_stdout(self) -> None:
        self.write("Cargo.toml", "[package]\nname='x'\nversion='0.1.0'\n")
        self.write("src/main.rs", 'const V:&str="2024-11-05"; fn main(){println!("jsonrpc");}')
        codes = self.codes()
        self.assertTrue({"handwritten-jsonrpc", "stale-protocol", "stdout-pollution"} <= codes)

    def test_flags_unbounded_network_and_process_sinks(self) -> None:
        self.write("Cargo.toml", "[package]\nname='x'\nversion='0.1.0'\n[dependencies]\nrmcp='3.0'\n")
        self.write("src/lib.rs", "async fn x(r:reqwest::Response,c:tokio::process::Child){let _=r.text().await;let _=c.wait_with_output().await;}")
        codes = self.codes()
        self.assertIn("unbounded-http-body", codes)
        self.assertIn("unbounded-subprocess-output", codes)

    def test_clean_server_has_no_medium_or_high_findings(self) -> None:
        self.write("Cargo.toml", "[package]\nname='x'\nversion='0.1.0'\n[dependencies]\nrmcp='3.0'\n")
        self.write("Cargo.lock", "# lock\n")
        self.write("src/lib.rs", "pub fn bounded(){}\n#[cfg(test)] mod tests{#[test] fn ok(){}}\n")
        self.write(".github/workflows/ci.yml", "name: ci\n")
        findings = module.audit(self.root)
        self.assertFalse(any(item.severity in {"medium", "high"} for item in findings), findings)


if __name__ == "__main__":
    unittest.main()
