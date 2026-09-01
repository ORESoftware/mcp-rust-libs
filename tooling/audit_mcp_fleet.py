#!/usr/bin/env python3
"""Discover, deduplicate, and statically audit the local Rust MCP fleet.

The historical ``fleet/inventory.json`` remains immutable evidence of an older
GitHub-App view. This tool derives a current inventory from standalone local
checkouts, canonicalizes their GitHub origins, selects one authoritative
checkout per repository, and runs the shared per-repository auditor.

Submodule/deployment copies are deliberately excluded. A duplicate standalone
checkout remains visible in the report but is never counted twice.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
REPOSITORY_SUFFIX = "-mcp-server.rs"
IGNORED_COMPONENTS = frozenset(
    {
        ".cache",
        ".git",
        ".idea",
        ".vscode",
        "apps",
        "dd",
        "node_modules",
        "repository-seeds",
        "target",
        "vendor",
    }
)
SCP_GITHUB_ORIGIN = re.compile(
    r"^(?:[^@/]+@)?github\.com:(?P<owner>[^/]+)/(?P<repository>[^/]+?)(?:\.git)?$",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True)
class GitState:
    root: Path | None
    origin: str | None
    repository: str | None
    revision: str | None
    branch: str | None
    dirty: bool | None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class Candidate:
    path: Path
    relative_path: str
    git: GitState


def _run_git(path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(path), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    return completed.stdout.strip()


def canonical_github_repository(origin: str | None) -> str | None:
    """Return ``owner/repository`` for exact github.com SSH/HTTPS origins."""

    if not origin:
        return None
    candidate = origin.strip()
    scp_match = SCP_GITHUB_ORIGIN.fullmatch(candidate)
    if scp_match is not None:
        owner = scp_match.group("owner")
        repository = scp_match.group("repository")
    else:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https", "ssh"}:
            return None
        if (parsed.hostname or "").casefold() != "github.com":
            return None
        pieces = [piece for piece in parsed.path.split("/") if piece]
        if len(pieces) != 2:
            return None
        owner, repository = pieces
        if repository.endswith(".git"):
            repository = repository[:-4]
    if not owner or not repository or owner in {".", ".."} or repository in {".", ".."}:
        return None
    return f"{owner}/{repository}"


def _contains_deployment_copy(parts: Iterable[str]) -> bool:
    lowered = tuple(part.casefold() for part in parts)
    return any(
        lowered[index : index + 2] == ("remote", "deployments")
        for index in range(max(0, len(lowered) - 1))
    )


def discover_repository_roots(workspace_root: Path) -> list[Path]:
    """Find standalone-looking ``*-mcp-server.rs`` directories portably."""

    resolved = workspace_root.resolve()
    discovered: list[Path] = []
    for current, directories, files in os.walk(resolved, followlinks=False):
        current_path = Path(current)
        relative_parts = current_path.relative_to(resolved).parts
        if any(part.casefold() in IGNORED_COMPONENTS for part in relative_parts):
            directories[:] = []
            continue
        if _contains_deployment_copy(relative_parts):
            directories[:] = []
            continue
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.casefold() not in IGNORED_COMPONENTS
        )
        if current_path.name.endswith(REPOSITORY_SUFFIX) and "Cargo.toml" in files:
            discovered.append(current_path.resolve())
            directories[:] = []
    return sorted(set(discovered), key=lambda path: path.as_posix().casefold())


def inspect_git(path: Path) -> GitState:
    """Read repository identity without changing the checkout."""

    try:
        root = Path(_run_git(path, "rev-parse", "--show-toplevel")).resolve()
        origin = _run_git(path, "remote", "get-url", "origin")
        revision = _run_git(path, "rev-parse", "HEAD")
        branch = _run_git(path, "rev-parse", "--abbrev-ref", "HEAD")
        status = _run_git(
            path,
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--ignore-submodules=all",
        )
    except (OSError, subprocess.SubprocessError) as error:
        return GitState(None, None, None, None, None, None, type(error).__name__)
    return GitState(
        root=root,
        origin=origin,
        repository=canonical_github_repository(origin),
        revision=revision,
        branch=branch,
        dirty=bool(status),
    )


def collect_candidates(workspace_root: Path) -> list[Candidate]:
    resolved = workspace_root.resolve()
    return [
        Candidate(
            path=path,
            relative_path=path.relative_to(resolved).as_posix(),
            git=inspect_git(path),
        )
        for path in discover_repository_roots(resolved)
    ]


def _authority_score(candidate: Candidate) -> tuple[int, int, str]:
    """Prefer the checkout whose path mirrors its GitHub owner/repository."""

    pieces = candidate.relative_path.split("/")
    repository = candidate.git.repository or ""
    remote_pieces = repository.split("/", 1)
    mirrors_remote = (
        len(remote_pieces) == 2
        and len(pieces) == 2
        and pieces[0].casefold() == remote_pieces[0].casefold()
        and pieces[1].casefold() == remote_pieces[1].casefold()
    )
    owner_container = (
        len(remote_pieces) == 2
        and bool(pieces)
        and pieces[0].casefold() == remote_pieces[0].casefold()
    )
    location_rank = 0 if mirrors_remote else 1 if owner_container else 2
    return location_rank, len(pieces), candidate.relative_path.casefold()


def select_authoritative(
    candidates: Iterable[Candidate],
) -> tuple[list[Candidate], list[tuple[Candidate, Candidate]], list[Candidate]]:
    """Select one standalone checkout for each canonical GitHub repository."""

    grouped: dict[str, list[Candidate]] = {}
    unclassified: list[Candidate] = []
    for candidate in candidates:
        if candidate.git.repository is None or candidate.git.root != candidate.path:
            unclassified.append(candidate)
            continue
        grouped.setdefault(candidate.git.repository.casefold(), []).append(candidate)

    authoritative: list[Candidate] = []
    duplicates: list[tuple[Candidate, Candidate]] = []
    for key in sorted(grouped):
        ordered = sorted(grouped[key], key=_authority_score)
        selected = ordered[0]
        authoritative.append(selected)
        duplicates.extend((candidate, selected) for candidate in ordered[1:])
    return authoritative, duplicates, sorted(
        unclassified, key=lambda candidate: candidate.relative_path.casefold()
    )


def _load_repository_auditor() -> Callable[[Path], list[Any]]:
    path = Path(__file__).with_name("audit_rust_mcp_server.py")
    spec = importlib.util.spec_from_file_location("ore_mcp_repository_auditor", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("shared repository auditor could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.audit


def _finding_dict(finding: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(finding):
        return dataclasses.asdict(finding)
    if isinstance(finding, dict):
        return dict(finding)
    raise TypeError(f"unsupported finding type: {type(finding).__name__}")


def _audit_candidate(
    candidate: Candidate, auditor: Callable[[Path], list[Any]]
) -> list[dict[str, Any]]:
    try:
        return [_finding_dict(finding) for finding in auditor(candidate.path)]
    except (OSError, UnicodeError, ValueError) as error:
        return [
            {
                "severity": "high",
                "code": "repository-audit-failed",
                "message": f"shared repository audit failed: {type(error).__name__}",
                "path": None,
            }
        ]


def _organization_class(repository: str) -> str:
    owner = repository.split("/", 1)[0]
    return "test" if owner.casefold().endswith("-test") else "production"


def build_report(
    workspace_root: Path,
    *,
    as_of: str,
    auditor: Callable[[Path], list[Any]] | None = None,
) -> dict[str, Any]:
    """Build the current exact-revision fleet report."""

    candidates = collect_candidates(workspace_root)
    authoritative, duplicates, unclassified = select_authoritative(candidates)
    audit_repository = auditor or _load_repository_auditor()
    repositories: list[dict[str, Any]] = []
    severity_totals: Counter[str] = Counter()
    code_totals: Counter[str] = Counter()
    repositories_with_high_findings = 0
    for candidate in authoritative:
        findings = _audit_candidate(candidate, audit_repository)
        severities = Counter(str(finding.get("severity")) for finding in findings)
        codes = Counter(str(finding.get("code")) for finding in findings)
        severity_totals.update(severities)
        code_totals.update(codes)
        repositories_with_high_findings += int(severities["high"] > 0)
        repository = candidate.git.repository
        assert repository is not None
        repositories.append(
            {
                "repository": repository,
                "organizationClass": _organization_class(repository),
                "checkout": candidate.relative_path,
                "revision": candidate.git.revision,
                "branch": candidate.git.branch,
                "dirty": candidate.git.dirty,
                "summary": {level: severities[level] for level in RANK},
                "findingCodes": dict(sorted(codes.items())),
                "findings": findings,
            }
        )

    return {
        "schemaVersion": 1,
        "asOf": as_of,
        "scope": "standalone local GitHub checkouts under the declared workspace root",
        "workspace": ".",
        "summary": {
            "candidateCheckouts": len(candidates),
            "authoritativeRepositories": len(authoritative),
            "productionOrganizations": len(
                {
                    item["repository"].split("/", 1)[0].casefold()
                    for item in repositories
                    if item["organizationClass"] == "production"
                }
            ),
            "testOrganizations": len(
                {
                    item["repository"].split("/", 1)[0].casefold()
                    for item in repositories
                    if item["organizationClass"] == "test"
                }
            ),
            "duplicateCheckouts": len(duplicates),
            "unclassifiedCheckouts": len(unclassified),
            "dirtyAuthoritativeCheckouts": sum(
                item["dirty"] is True for item in repositories
            ),
            "repositoriesWithHighFindings": repositories_with_high_findings,
            "findings": {level: severity_totals[level] for level in RANK},
        },
        "findingCodeTotals": dict(sorted(code_totals.items())),
        "repositories": repositories,
        "duplicateCheckouts": [
            {
                "repository": duplicate.git.repository,
                "checkout": duplicate.relative_path,
                "authoritativeCheckout": selected.relative_path,
                "revision": duplicate.git.revision,
                "dirty": duplicate.git.dirty,
            }
            for duplicate, selected in duplicates
        ],
        "unclassifiedCheckouts": [
            {
                "checkout": candidate.relative_path,
                "origin": candidate.git.origin,
                "gitRoot": (
                    candidate.git.root.as_posix() if candidate.git.root is not None else None
                ),
                "reason": (
                    "not-standalone"
                    if candidate.git.root is not None and candidate.git.root != candidate.path
                    else "missing-or-non-github-origin"
                ),
                "error": candidate.git.error,
            }
            for candidate in unclassified
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"# Rust MCP fleet audit — {report['asOf']}",
        "",
        "This is a current local-checkout audit. The historical inventory remains unchanged.",
        "",
        f"- Authoritative repositories: {summary['authoritativeRepositories']}",
        f"- Production organizations: {summary['productionOrganizations']}",
        f"- Test organizations: {summary['testOrganizations']}",
        f"- Duplicate checkouts: {summary['duplicateCheckouts']}",
        f"- Unclassified checkouts: {summary['unclassifiedCheckouts']}",
        f"- Dirty authoritative checkouts: {summary['dirtyAuthoritativeCheckouts']}",
        f"- Repositories with high findings: {summary['repositoriesWithHighFindings']}",
        "",
        "| Repository | Class | Checkout | Revision | Dirty | High | Medium | Low | Info |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in report["repositories"]:
        item_summary = item["summary"]
        lines.append(
            "| {repository} | {organizationClass} | `{checkout}` | `{revision}` | {dirty} | {high} | {medium} | {low} | {info} |".format(
                repository=item["repository"],
                organizationClass=item["organizationClass"],
                checkout=item["checkout"],
                revision=(item["revision"] or "unknown")[:12],
                dirty="yes" if item["dirty"] else "no",
                **item_summary,
            )
        )

    lines.extend(["", "## Finding-code totals", ""])
    for code, count in report["findingCodeTotals"].items():
        lines.append(f"- `{code}`: {count}")
    if report["duplicateCheckouts"]:
        lines.extend(["", "## Duplicate checkouts", ""])
        for item in report["duplicateCheckouts"]:
            lines.append(
                f"- `{item['checkout']}` duplicates `{item['authoritativeCheckout']}` for {item['repository']}."
            )
    if report["unclassifiedCheckouts"]:
        lines.extend(["", "## Unclassified checkouts", ""])
        for item in report["unclassifiedCheckouts"]:
            lines.append(f"- `{item['checkout']}`: {item['reason']}")
    return "\n".join(lines) + "\n"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--as-of", default=date.today().isoformat())
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--markdown-report", type=Path)
    parser.add_argument("--fail-on", choices=("none", *RANK), default="none")
    args = parser.parse_args(argv)

    report = build_report(args.workspace_root, as_of=args.as_of)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_report is None:
        sys.stdout.write(rendered)
    else:
        _write(args.json_report, rendered)
    if args.markdown_report is not None:
        _write(args.markdown_report, render_markdown(report))

    if args.fail_on == "none":
        return 0
    threshold = RANK[args.fail_on]
    return int(
        any(
            RANK[level] >= threshold and count > 0
            for level, count in report["summary"]["findings"].items()
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
