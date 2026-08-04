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

    def standard_manifest(self, rmcp: str = "2.2.0") -> None:
        self.write(
            "Cargo.toml",
            f"[package]\nname='x'\nversion='0.1.0'\n[dependencies]\nrmcp='{rmcp}'\n",
        )
        self.write("Cargo.lock", "# lock\n")

    def standard_workflow(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            """name: ci
permissions:
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
""",
        )

    def process_test(self) -> None:
        self.write(
            "tests/stdio_protocol.rs",
            'fn x(){let _=env!("CARGO_BIN_EXE_x");let _="initialize";}\n',
        )

    def test_semver_parser_handles_ranges_and_missing_patch(self) -> None:
        self.assertEqual(module.semver_tuple("2.2"), (2, 2, 0))
        self.assertEqual(module.semver_tuple("^1.4.0"), (1, 4, 0))
        self.assertIsNone(module.semver_tuple("workspace"))
        self.assertTrue(module.semver_is_prerelease("^1.4.0-rc.1"))
        self.assertFalse(module.semver_is_prerelease("^1.4.0"))

    def test_flags_handwritten_stale_stdout(self) -> None:
        self.write("Cargo.toml", "[package]\nname='x'\nversion='0.1.0'\n")
        self.write("src/main.rs", 'const V:&str="2024-11-05"; fn main(){println!("jsonrpc");}')
        codes = self.codes()
        self.assertTrue({"handwritten-jsonrpc", "stale-protocol", "stdout-pollution"} <= codes)

    def test_flags_vulnerable_streamable_http_rmcp_floor(self) -> None:
        self.standard_manifest("1.3.2")
        self.write(
            "src/lib.rs",
            'fn x(){let _=StreamableHttpService::new;let _="Bearer ";let _="allowed_hosts";let _="Policy::none";let _=".no_proxy()";}',
        )
        self.assertIn("rmcp-dns-rebinding-floor", self.codes())

    def test_final_floor_prerelease_is_still_vulnerable(self) -> None:
        self.standard_manifest("1.4.0-rc.1")
        self.write(
            "src/lib.rs",
            'fn x(){let _=StreamableHttpService::new;let _="Bearer ";let _="allowed_hosts";let _="Policy::none";let _=".no_proxy()";}',
        )
        self.assertIn("rmcp-dns-rebinding-floor", self.codes())

    def test_pre_1_rmcp_is_review_signal_but_not_false_3x_requirement(self) -> None:
        self.standard_manifest("0.16.0")
        self.write("src/lib.rs", "pub fn x(){}\n")
        codes = self.codes()
        self.assertIn("rmcp-prestable", codes)
        self.assertNotIn("rmcp-major", codes)

    def test_rmcp_2_2_has_no_version_finding(self) -> None:
        self.standard_manifest("2.2.0")
        self.write("src/lib.rs", "pub fn x(){}\n")
        codes = self.codes()
        self.assertFalse(any(code.startswith("rmcp-") for code in codes), codes)

    def test_flags_unbounded_network_and_process_sinks(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            "async fn x(r:reqwest::Response,c:tokio::process::Child){let _=r.bytes().await;let _=c.wait_with_output().await;}",
        )
        codes = self.codes()
        self.assertIn("unbounded-http-body", codes)
        self.assertIn("unbounded-subprocess-output", codes)

    def test_flags_bearer_redirect_proxy_and_host_policy(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            'fn x(c:reqwest::Client,u:url::Url){let _=c.get(u).bearer_auth("secret");let _="base_url";}',
        )
        codes = self.codes()
        self.assertTrue(
            {"bearer-redirect-policy", "bearer-proxy-policy", "bearer-host-policy"} <= codes
        )

    def test_flags_permissive_mutation_and_unbounded_output(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            """
use rmcp::{tool,handler::server::wrapper::Parameters};
use serde::Deserialize;
#[derive(Deserialize)] struct Input { value:String }
#[tool] async fn create_job(Parameters(_):Parameters<Input>)->String {
    serde_json::to_string_pretty(&serde_json::json!({"ok":true})).unwrap()
}
""",
        )
        codes = self.codes()
        self.assertTrue(
            {"permissive-tool-schema", "mutation-gate", "unbounded-tool-output"} <= codes
        )

    def test_flags_streamable_http_without_auth_or_host_boundary(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            "fn x(){let _=StreamableHttpService::new;let _=\"transport-streamable-http\";}",
        )
        codes = self.codes()
        self.assertTrue({"http-auth-boundary", "http-host-boundary"} <= codes)
        self.assertNotIn("rmcp-dns-rebinding-floor", codes)

    def test_flags_mutable_actions_and_implicit_permissions(self) -> None:
        self.standard_manifest()
        self.write("src/lib.rs", "#[cfg(test)] mod tests{#[test] fn ok(){}}\n")
        self.process_test()
        self.write(
            ".github/workflows/ci.yml",
            "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        codes = self.codes()
        self.assertTrue({"mutable-action-pin", "workflow-permissions", "checkout-credentials"} <= codes)

    def test_each_checkout_step_must_discard_its_own_credentials(self) -> None:
        self.standard_manifest()
        self.write("src/lib.rs", "#[cfg(test)] mod tests{#[test] fn ok(){}}\n")
        self.process_test()
        self.write(
            ".github/workflows/ci.yml",
            """name: ci
permissions:
  contents: read
jobs:
  test:
    steps:
      - name: Safe checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Unsafe second checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
""",
        )
        self.assertIn("checkout-credentials", self.codes())

    def test_named_checkout_with_quoted_false_is_accepted(self) -> None:
        self.standard_manifest()
        self.write("src/lib.rs", "#[cfg(test)] mod tests{#[test] fn ok(){}}\n")
        self.process_test()
        self.write(
            ".github/workflows/ci.yml",
            """name: ci
permissions:
  contents: read
jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: "false"
""",
        )
        self.assertNotIn("checkout-credentials", self.codes())

    def test_production_after_cfg_test_module_is_still_scanned(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            """
#[cfg(test)]
mod tests {
    #[test]
    fn test_only() { println!("test output"); }
}

pub fn production() { println!("production stdout"); }
""",
        )
        self.assertIn("stdout-pollution", self.codes())

    def test_stdout_inside_exact_cfg_test_module_is_ignored(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            """
#[cfg(test)]
mod tests {
    #[test]
    fn test_only() { println!("test output"); }
}

pub fn production() {}
""",
        )
        self.assertNotIn("stdout-pollution", self.codes())

    def test_clean_server_has_no_medium_or_high_findings(self) -> None:
        self.standard_manifest()
        self.write(
            "src/lib.rs",
            """
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input { value:String }
const MAX_TOOL_OUTPUT_BYTES:usize=1024;
pub fn bounded(){}
#[cfg(test)] mod tests{#[test] fn ok(){}}
""",
        )
        self.standard_workflow()
        self.process_test()
        findings = module.audit(self.root)
        self.assertFalse(any(item.severity in {"medium", "high"} for item in findings), findings)


if __name__ == "__main__":
    unittest.main()
