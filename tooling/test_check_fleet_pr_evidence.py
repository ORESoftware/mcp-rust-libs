from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check_fleet_pr_evidence.py")
SPEC = importlib.util.spec_from_file_location("check_fleet_pr_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def sha(char: str) -> str:
    return char * 40


def inventory() -> dict:
    return {
        "existing": ["org/server.rs"],
        "sharedRepository": "core/libs",
    }


def entry(**overrides: object) -> dict:
    value = {
        "repository": "org/server.rs",
        "pullRequest": 7,
        "purpose": "server-hardening",
        "expectedState": "merged",
        "expectedHeadSha": sha("a"),
        "expectedMergeSha": sha("b"),
        "titleMustContainAny": ["harden"],
        "linear": "DEN-7",
    }
    value.update(overrides)
    return value


def document() -> dict:
    return {
        "schemaVersion": 1,
        "asOf": "2026-08-04",
        "scope": "test batch",
        "expectedServerCount": 1,
        "servers": [entry()],
        "sharedCore": entry(
            repository="core/libs",
            pullRequest=4,
            purpose="fleet-audit",
            expectedHeadSha=sha("c"),
            expectedMergeSha=sha("d"),
            titleMustContainAny=["audit"],
        ),
    }


def payload(
    *,
    repository: str = "org/server.rs",
    number: int = 7,
    title: str = "Harden the server boundary",
    state: str = "closed",
    draft: bool = False,
    head_sha: str | None = None,
    merged_at: str | None = "2026-08-04T12:00:00Z",
    merge_sha: str | None = None,
) -> dict:
    return {
        "number": number,
        "title": title,
        "state": state,
        "draft": draft,
        "merged_at": merged_at,
        "merge_commit_sha": merge_sha or sha("b"),
        "base": {"repo": {"full_name": repository}},
        "head": {"sha": head_sha or sha("a")},
    }


class DocumentValidationTests(unittest.TestCase):
    def test_valid_document_cross_checks_inventory(self) -> None:
        servers, shared = checker.validate_document(document(), inventory())
        self.assertEqual(len(servers), 1)
        self.assertEqual(shared["repository"], "core/libs")

    def test_rejects_wrong_server_count(self) -> None:
        doc = document()
        doc["expectedServerCount"] = 2
        with self.assertRaisesRegex(checker.EvidenceError, "count"):
            checker.validate_document(doc, inventory())

    def test_rejects_repository_outside_inventory(self) -> None:
        doc = document()
        doc["servers"][0]["repository"] = "other/server.rs"
        with self.assertRaisesRegex(checker.EvidenceError, "not present"):
            checker.validate_document(doc, inventory())

    def test_rejects_duplicate_repository_even_with_different_pr(self) -> None:
        doc = document()
        doc["expectedServerCount"] = 2
        duplicate = copy.deepcopy(doc["servers"][0])
        duplicate["pullRequest"] = 8
        doc["servers"].append(duplicate)
        with self.assertRaisesRegex(checker.EvidenceError, "more than once"):
            checker.validate_document(doc, inventory())

    def test_rejects_uppercase_or_short_sha(self) -> None:
        doc = document()
        doc["servers"][0]["expectedHeadSha"] = "A" * 40
        with self.assertRaisesRegex(checker.EvidenceError, "lowercase hex"):
            checker.validate_document(doc, inventory())

    def test_rejects_merge_sha_on_open_pr(self) -> None:
        doc = document()
        doc["servers"][0]["expectedState"] = "open_draft"
        with self.assertRaisesRegex(checker.EvidenceError, "only allowed"):
            checker.validate_document(doc, inventory())

    def test_rejects_routing_pr_disguised_as_hardening(self) -> None:
        server = entry()
        live = payload(title="DEN-1279 Add alex-main-agent routing")
        with self.assertRaisesRegex(checker.EvidenceError, "recorded purpose"):
            checker.validate_live_pull(server, live)


class LiveValidationTests(unittest.TestCase):
    def test_valid_merged_pull(self) -> None:
        checker.validate_live_pull(entry(), payload())

    def test_detects_head_drift(self) -> None:
        with self.assertRaisesRegex(checker.EvidenceError, "head drifted"):
            checker.validate_live_pull(entry(), payload(head_sha=sha("e")))

    def test_detects_state_drift(self) -> None:
        open_entry = entry(expectedState="open_draft")
        open_entry.pop("expectedMergeSha")
        with self.assertRaisesRegex(checker.EvidenceError, "state drifted"):
            checker.validate_live_pull(open_entry, payload())

    def test_valid_open_draft_pull(self) -> None:
        open_entry = entry(expectedState="open_draft")
        open_entry.pop("expectedMergeSha")
        live = payload(
            state="open",
            draft=True,
            merged_at=None,
            merge_sha=sha("f"),
        )
        checker.validate_live_pull(open_entry, live)

    def test_detects_merge_sha_drift(self) -> None:
        with self.assertRaisesRegex(checker.EvidenceError, "merge SHA drifted"):
            checker.validate_live_pull(entry(), payload(merge_sha=sha("e")))

    def test_detects_wrong_base_repository(self) -> None:
        with self.assertRaisesRegex(checker.EvidenceError, "recorded repository"):
            checker.validate_live_pull(
                entry(), payload(repository="other/server.rs")
            )


if __name__ == "__main__":
    unittest.main()
