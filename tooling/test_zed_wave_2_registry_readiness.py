from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/zed_wave_2_registry_readiness.py"
MANIFEST = ROOT / "fleet/zed-wave-2-packages.json"
WORKFLOW = ROOT / ".github/workflows/zed-wave-2-registry-readiness.yml"
SPEC = importlib.util.spec_from_file_location("zed_wave_2_registry_readiness", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class RegistryReadinessTests(unittest.TestCase):
    def run_probe(self, error_code: int) -> tuple[int, dict[str, object]]:
        with tempfile.TemporaryDirectory() as temporary:
            evidence_path = Path(temporary) / "evidence.json"
            args = SimpleNamespace(manifest=MANIFEST, evidence=evidence_path)
            error = urllib.error.HTTPError(
                url="https://registry.zpkg.net",
                code=error_code,
                msg="synthetic registry response",
                hdrs=None,
                fp=None,
            )
            with (
                mock.patch.object(module.urllib.request, "urlopen", side_effect=error) as urlopen,
                mock.patch.dict(
                    os.environ,
                    {"GITHUB_OUTPUT": "", "GITHUB_STEP_SUMMARY": ""},
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                status = module.run(args)
            self.assertEqual(urlopen.call_count, 23)
            self.assertTrue(evidence_path.is_file())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertFalse((evidence_path.parent / ".evidence.json.tmp").exists())
            return status, evidence

    def test_http_530_fails_after_persisting_full_probe_evidence(self) -> None:
        status, evidence = self.run_probe(530)

        self.assertEqual(status, 1)
        self.assertEqual(evidence["status"], "failed")
        self.assertFalse(evidence["allReady"])
        self.assertEqual(evidence["packageCount"], 23)
        self.assertEqual(evidence["blockedCount"], 23)
        self.assertEqual(evidence["probeErrorCount"], 23)
        self.assertEqual(len(evidence["packages"]), 23)
        self.assertTrue(
            all(package["httpStatus"] == 530 for package in evidence["packages"])
        )
        self.assertTrue(
            all(package["state"] == "probe-error" for package in evidence["packages"])
        )
        self.assertTrue(
            all(
                error["kind"] == "unexpected-http-status"
                and error["message"] == "unexpected HTTP 530"
                for error in evidence["probeErrors"]
            )
        )

    def test_http_404_remains_a_nonfatal_readiness_blocker(self) -> None:
        status, evidence = self.run_probe(404)

        self.assertEqual(status, 0)
        self.assertEqual(evidence["status"], "complete")
        self.assertFalse(evidence["allReady"])
        self.assertEqual(evidence["blockedCount"], 23)
        self.assertEqual(evidence["probeErrorCount"], 0)
        self.assertEqual(evidence["probeErrors"], [])
        self.assertTrue(
            all(package["state"] == "not-published" for package in evidence["packages"])
        )

    def test_setup_failure_still_writes_bounded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "invalid.json"
            evidence_path = root / "evidence.json"
            manifest.write_text("{not-json}\n", encoding="utf-8")
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        str(SCRIPT),
                        "--manifest",
                        str(manifest),
                        "--evidence",
                        str(evidence_path),
                    ],
                ),
                mock.patch.dict(
                    os.environ,
                    {"GITHUB_OUTPUT": "", "GITHUB_STEP_SUMMARY": ""},
                ),
                redirect_stderr(io.StringIO()),
            ):
                status = module.main()

            self.assertEqual(status, 1)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["probeErrorCount"], 1)
            self.assertEqual(
                evidence["probeErrors"][0]["kind"], "probe-setup-error"
            )
            self.assertLessEqual(
                len(evidence["probeErrors"][0]["message"]),
                module.ERROR_MESSAGE_LIMIT,
            )

    def test_workflow_upload_is_strict_current_and_bounded(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("concurrency:", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            workflow,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            workflow,
        )
        self.assertIn("if-no-files-found: error", workflow)


if __name__ == "__main__":
    unittest.main()
