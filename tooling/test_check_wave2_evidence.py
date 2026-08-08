from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("check_wave2_evidence.py")
SPEC = importlib.util.spec_from_file_location("wave2_evidence", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class Wave2EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wave = module.load_json(module.DEFAULT_WAVE)
        cls.provenance = module.load_json(module.DEFAULT_PROVENANCE)

    def errors(self, wave=None, provenance=None) -> list[str]:
        return module.validate_documents(
            copy.deepcopy(self.wave if wave is None else wave),
            copy.deepcopy(self.provenance if provenance is None else provenance),
        )

    def test_committed_ledgers_pass(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_runtime_cannot_regress_to_incomplete(self) -> None:
        wave = copy.deepcopy(self.wave)
        wave["protocolPolicy"]["runtimeMigrationComplete"] = False
        errors = self.errors(wave=wave)
        self.assertTrue(any("runtime migration" in error for error in errors), errors)

    def test_preview_cannot_be_enabled(self) -> None:
        wave = copy.deepcopy(self.wave)
        wave["protocolPolicy"]["previewEnabled"] = True
        errors = self.errors(wave=wave)
        self.assertTrue(any("preview protocol" in error for error in errors), errors)

    def test_consumer_requires_two_exact_head_runs(self) -> None:
        wave = copy.deepcopy(self.wave)
        wave["consumers"][0]["runtime"]["workflowRuns"] = [31268502539]
        errors = self.errors(wave=wave)
        self.assertTrue(any("two positive exact-head runs" in error for error in errors), errors)

    def test_consumer_cannot_claim_frozen_install(self) -> None:
        wave = copy.deepcopy(self.wave)
        wave["consumers"][0]["zed"]["frozenInstall"] = True
        errors = self.errors(wave=wave)
        self.assertTrue(any("frozen Zed installation" in error for error in errors), errors)

    def test_publication_monitor_cannot_claim_partial_readiness(self) -> None:
        wave = copy.deepcopy(self.wave)
        wave["publicationClosure"]["readyPackages"] = 1
        errors = self.errors(wave=wave)
        self.assertTrue(any("publication readiness" in error for error in errors), errors)

    def test_test_org_matrix_requires_six_jobs(self) -> None:
        provenance = copy.deepcopy(self.provenance)
        embedded = next(
            record
            for record in provenance["runtimeConsumers"]
            if record["productionRepository"]
            == "embedded-alerts/eal-mcp-server.rs"
        )
        embedded["matrixJobs"] = 5
        errors = self.errors(provenance=provenance)
        self.assertTrue(any("matrixJobs must equal 6" in error for error in errors), errors)

    def test_blocked_test_org_cannot_claim_connection(self) -> None:
        provenance = copy.deepcopy(self.provenance)
        apostille = next(
            record
            for record in provenance["runtimeConsumers"]
            if record["productionRepository"]
            == "apostille-me/apme-mcp-server.rs"
        )
        apostille["connectedRepository"] = True
        errors = self.errors(provenance=provenance)
        self.assertTrue(any("falsely claims a connected repository" in error for error in errors), errors)

    def test_cross_ledger_merge_mismatch_fails(self) -> None:
        provenance = copy.deepcopy(self.provenance)
        provenance["runtimeConsumers"][0]["productionMerge"] = "0" * 40
        errors = self.errors(provenance=provenance)
        self.assertTrue(any("production merge differs" in error for error in errors), errors)

    def test_provider_consensus_cannot_be_claimed(self) -> None:
        provenance = copy.deepcopy(self.provenance)
        provenance["qualification"]["providerBackedAiConsensus"] = True
        errors = self.errors(provenance=provenance)
        self.assertTrue(any("providerBackedAiConsensus" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
