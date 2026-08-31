from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PATH = Path(__file__).with_name("audit_mcp_fleet.py")
SPEC = importlib.util.spec_from_file_location("mcp_fleet_audit", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def git_state(
    root: Path,
    repository: str,
    *,
    revision: str = "a" * 40,
    dirty: bool = False,
) -> module.GitState:
    return module.GitState(
        root=root,
        origin=f"git@github.com:{repository}.git",
        repository=repository,
        revision=revision,
        branch="main",
        dirty=dirty,
    )


class FleetAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_candidate(
        self,
        relative: str,
        repository: str,
        *,
        revision: str = "a" * 40,
        dirty: bool = False,
    ) -> module.Candidate:
        path = (self.workspace / relative).resolve()
        return module.Candidate(
            path=path,
            relative_path=relative,
            git=git_state(path, repository, revision=revision, dirty=dirty),
        )

    def test_canonicalizes_exact_github_origins(self) -> None:
        expected = "Example/example-mcp-server.rs"
        self.assertEqual(
            module.canonical_github_repository(
                "git@github.com:Example/example-mcp-server.rs.git"
            ),
            expected,
        )
        self.assertEqual(
            module.canonical_github_repository(
                "https://github.com/Example/example-mcp-server.rs.git"
            ),
            expected,
        )
        self.assertEqual(
            module.canonical_github_repository(
                "ssh://git@github.com/Example/example-mcp-server.rs.git"
            ),
            expected,
        )

    def test_rejects_non_github_or_ambiguous_origins(self) -> None:
        for origin in (
            None,
            "",
            "git@example.com:owner/repo.git",
            "https://github.example.com/owner/repo.git",
            "https://github.com/owner/nested/repo.git",
            "file:///tmp/repo",
        ):
            with self.subTest(origin=origin):
                self.assertIsNone(module.canonical_github_repository(origin))

    def test_discovery_excludes_secondary_and_build_copies(self) -> None:
        included = self.workspace / "example" / "example-mcp-server.rs"
        excluded = (
            self.workspace / "example" / "example-monorepo" / "apps" / "app-mcp-server.rs",
            self.workspace
            / "oresoftware"
            / "k8s-cluster"
            / "remote"
            / "deployments"
            / "deploy-mcp-server.rs",
            self.workspace / "dd" / "private-mcp-server.rs",
            self.workspace
            / "example"
            / ".github"
            / "repository-seeds"
            / "seed-mcp-server.rs",
            included / "target" / "generated-mcp-server.rs",
        )
        for path in (included, *excluded):
            path.mkdir(parents=True)
            (path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")

        self.assertEqual(module.discover_repository_roots(self.workspace), [included.resolve()])

    def test_authority_prefers_owner_repository_path(self) -> None:
        nested = self.make_candidate(
            "canonical-cloud/canonical.cloud/canonical-mcp-server.rs",
            "canonical-cloud/canonical-mcp-server.rs",
        )
        direct = self.make_candidate(
            "canonical-cloud/canonical-mcp-server.rs",
            "canonical-cloud/canonical-mcp-server.rs",
        )

        authoritative, duplicates, unclassified = module.select_authoritative(
            [nested, direct]
        )

        self.assertEqual(authoritative, [direct])
        self.assertEqual(duplicates, [(nested, direct)])
        self.assertEqual(unclassified, [])

    def test_non_standalone_and_unknown_origins_are_unclassified(self) -> None:
        parent = self.workspace / "org" / "monorepo"
        embedded_path = parent / "embedded-mcp-server.rs"
        embedded = module.Candidate(
            path=embedded_path,
            relative_path="org/monorepo/embedded-mcp-server.rs",
            git=module.GitState(
                root=parent,
                origin="git@github.com:org/monorepo.git",
                repository="org/monorepo",
                revision="a" * 40,
                branch="main",
                dirty=False,
            ),
        )
        unknown_path = self.workspace / "org" / "unknown-mcp-server.rs"
        unknown = module.Candidate(
            path=unknown_path,
            relative_path="org/unknown-mcp-server.rs",
            git=module.GitState(
                root=unknown_path,
                origin="https://example.com/org/unknown.git",
                repository=None,
                revision="b" * 40,
                branch="main",
                dirty=False,
            ),
        )

        authoritative, duplicates, unclassified = module.select_authoritative(
            [embedded, unknown]
        )

        self.assertEqual(authoritative, [])
        self.assertEqual(duplicates, [])
        self.assertEqual(set(unclassified), {embedded, unknown})

    def test_report_deduplicates_and_preserves_test_orgs(self) -> None:
        production = self.make_candidate(
            "example/example-mcp-server.rs",
            "example/example-mcp-server.rs",
            dirty=True,
        )
        duplicate = self.make_candidate(
            "copies/example-mcp-server.rs",
            "example/example-mcp-server.rs",
            revision="b" * 40,
        )
        test_org = self.make_candidate(
            "example-test/example-test-mcp-server.rs",
            "example-test/example-test-mcp-server.rs",
        )

        def auditor(path: Path) -> list[dict[str, object]]:
            severity = "high" if path == production.path else "medium"
            return [
                {
                    "severity": severity,
                    "code": f"{severity}-finding",
                    "message": "bounded fixture finding",
                    "path": None,
                }
            ]

        with mock.patch.object(
            module,
            "collect_candidates",
            return_value=[duplicate, test_org, production],
        ):
            report = module.build_report(
                self.workspace,
                as_of="2026-08-31",
                auditor=auditor,
            )

        self.assertEqual(report["summary"]["candidateCheckouts"], 3)
        self.assertEqual(report["summary"]["authoritativeRepositories"], 2)
        self.assertEqual(report["summary"]["productionOrganizations"], 1)
        self.assertEqual(report["summary"]["testOrganizations"], 1)
        self.assertEqual(report["summary"]["duplicateCheckouts"], 1)
        self.assertEqual(report["summary"]["dirtyAuthoritativeCheckouts"], 1)
        self.assertEqual(report["summary"]["repositoriesWithHighFindings"], 1)
        self.assertEqual(
            [item["repository"] for item in report["repositories"]],
            [
                "example-test/example-test-mcp-server.rs",
                "example/example-mcp-server.rs",
            ],
        )
        self.assertEqual(
            report["duplicateCheckouts"][0]["authoritativeCheckout"],
            "example/example-mcp-server.rs",
        )
        markdown = module.render_markdown(report)
        self.assertIn("Authoritative repositories: 2", markdown)
        self.assertIn("example-test/example-test-mcp-server.rs", markdown)

    def test_audit_failure_is_value_free_and_high_severity(self) -> None:
        candidate = self.make_candidate(
            "example/example-mcp-server.rs", "example/example-mcp-server.rs"
        )

        def failing_auditor(_: Path) -> list[object]:
            raise ValueError("secret provider response")

        findings = module._audit_candidate(candidate, failing_auditor)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["code"], "repository-audit-failed")
        self.assertNotIn("secret provider response", findings[0]["message"])

    def test_shared_repository_auditor_loads_with_dataclass_metadata(self) -> None:
        auditor = module._load_repository_auditor()
        self.assertTrue(callable(auditor))
        self.assertIn("ore_mcp_repository_auditor", sys.modules)


if __name__ == "__main__":
    unittest.main()
