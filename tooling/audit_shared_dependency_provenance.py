#!/usr/bin/env python3
"""Audit one Rust MCP consumer's shared-runtime and Zed provenance.

The check intentionally separates three claims:

* Cargo runtime adoption: at least one ``ore-mcp-*`` crate from the canonical
  repository at one full immutable revision;
* Zed graph declaration: ``.zpkg.toml`` declares the canonical package edge and
  uses a locked Cargo build;
* Zed frozen resolution: a regular, non-placeholder ``.zpkg.lock`` exists when
  that stronger gate is explicitly enabled.

This prevents a manifest-only package edge or ``version = 1`` placeholder from
being reported as a frozen install while the recursive Zed publication closure
remains blocked.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
import re
import sys
import tomllib
from typing import Callable
from urllib import error, parse, request

CANONICAL_GIT = "https://github.com/ORESoftware/mcp-rust-libs"
CANONICAL_ZED = "oresoftware/mcp-rust-libs"
CANONICAL_BRANCH = "main"
SHARED_DEPENDENCY = re.compile(r"^ore-mcp-[a-z0-9-]+$")
FULL_REVISION = re.compile(r"^[0-9a-f]{40}$")
LOCK_METADATA_KEYS = {"version", "schemaVersion", "lockfileVersion"}
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    path: str | None = None


def normalized_git_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.removesuffix(".git").rstrip("/")


def dependency_tables(manifest: dict[str, object]) -> list[dict[str, object]]:
    tables: list[dict[str, object]] = []
    direct = manifest.get("dependencies")
    if isinstance(direct, dict):
        tables.append(direct)
    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        workspace_dependencies = workspace.get("dependencies")
        if isinstance(workspace_dependencies, dict):
            tables.append(workspace_dependencies)
    return tables


def shared_dependencies(manifest: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for table in dependency_tables(manifest):
        for name, value in table.items():
            if isinstance(name, str) and SHARED_DEPENDENCY.fullmatch(name):
                result[name] = value
    return result


def read_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    if not isinstance(value, dict):
        raise ValueError("TOML root must be a table")
    return value


def lock_has_resolution_payload(lock: dict[str, object]) -> bool:
    """Reject metadata-only placeholders without guessing the final lock schema."""
    for key, value in lock.items():
        if key in LOCK_METADATA_KEYS:
            continue
        if isinstance(value, dict) and value:
            return True
        if isinstance(value, list) and value:
            return True
    return False


def github_compare_status(revision: str, *, timeout: float = 15.0) -> str:
    encoded_revision = parse.quote(revision, safe="")
    encoded_branch = parse.quote(CANONICAL_BRANCH, safe="")
    url = (
        "https://api.github.com/repos/ORESoftware/mcp-rust-libs/compare/"
        f"{encoded_revision}...{encoded_branch}"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ores-mcp-dependency-provenance/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = request.urlopen(request.Request(url, headers=headers), timeout=timeout)
    try:
        payload = json.load(response)
    finally:
        response.close()
    status = payload.get("status") if isinstance(payload, dict) else None
    if not isinstance(status, str):
        raise ValueError("GitHub compare response has no status")
    return status


def audit(
    root: Path,
    *,
    require_zed_lock: bool = False,
    verify_reachability: bool = False,
    compare_status: Callable[[str], str] = github_compare_status,
) -> list[Finding]:
    findings: list[Finding] = []
    cargo_path = root / "Cargo.toml"
    if not cargo_path.is_file() or cargo_path.is_symlink():
        return [Finding("high", "missing-cargo-manifest", "Cargo.toml must be a regular file", "Cargo.toml")]
    try:
        cargo = read_toml(cargo_path)
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return [Finding("high", "invalid-cargo-manifest", "Cargo.toml could not be parsed", "Cargo.toml")]

    dependencies = shared_dependencies(cargo)
    valid_revisions: dict[str, str] = {}
    if not dependencies:
        findings.append(
            Finding(
                "high",
                "missing-shared-mcp-runtime",
                "no canonical ore-mcp-* runtime/policy crate is declared",
                "Cargo.toml",
            )
        )
    for name, value in sorted(dependencies.items()):
        if not isinstance(value, dict):
            findings.append(
                Finding(
                    "high",
                    "unmanaged-shared-mcp-source",
                    f"{name} must use the canonical Git repository at a full immutable revision",
                    "Cargo.toml",
                )
            )
            continue
        forbidden = sorted(key for key in ("branch", "tag", "path") if key in value)
        if forbidden:
            findings.append(
                Finding(
                    "high",
                    "mutable-or-local-shared-mcp-source",
                    f"{name} contains forbidden source selectors: {', '.join(forbidden)}",
                    "Cargo.toml",
                )
            )
        if normalized_git_url(value.get("git")) != CANONICAL_GIT:
            findings.append(
                Finding(
                    "high",
                    "wrong-shared-mcp-repository",
                    f"{name} must resolve from {CANONICAL_GIT}",
                    "Cargo.toml",
                )
            )
        revision = value.get("rev")
        if not isinstance(revision, str) or FULL_REVISION.fullmatch(revision) is None:
            findings.append(
                Finding(
                    "high",
                    "invalid-shared-mcp-revision",
                    f"{name} must pin one lowercase 40-hex commit revision",
                    "Cargo.toml",
                )
            )
        elif normalized_git_url(value.get("git")) == CANONICAL_GIT and not forbidden:
            valid_revisions[name] = revision

    distinct_revisions = sorted(set(valid_revisions.values()))
    if len(distinct_revisions) > 1:
        findings.append(
            Finding(
                "high",
                "split-shared-mcp-revision",
                "ore-mcp-* crates resolve from different shared-repository revisions",
                "Cargo.toml",
            )
        )

    if verify_reachability:
        for revision in distinct_revisions:
            try:
                status = compare_status(revision)
            except (OSError, ValueError, error.URLError, TimeoutError):
                findings.append(
                    Finding(
                        "medium",
                        "shared-mcp-reachability-unverified",
                        "GitHub could not verify whether the pinned revision is reachable from canonical main",
                        "Cargo.toml",
                    )
                )
                continue
            if status not in {"ahead", "identical"}:
                findings.append(
                    Finding(
                        "high",
                        "unmerged-shared-mcp-revision",
                        f"pinned revision is not reachable from canonical main (compare status: {status})",
                        "Cargo.toml",
                    )
                )

    zed_path = root / ".zpkg.toml"
    zed_declared = False
    if not zed_path.is_file() or zed_path.is_symlink():
        findings.append(
            Finding(
                "high",
                "missing-zed-package-manifest",
                ".zpkg.toml must be a regular file declaring the shared package edge",
                ".zpkg.toml",
            )
        )
    else:
        try:
            zed = read_toml(zed_path)
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            findings.append(
                Finding("high", "invalid-zed-package-manifest", ".zpkg.toml could not be parsed", ".zpkg.toml")
            )
        else:
            zed_dependencies = zed.get("dependencies")
            requirement = zed_dependencies.get(CANONICAL_ZED) if isinstance(zed_dependencies, dict) else None
            if requirement != "^0.1.0":
                findings.append(
                    Finding(
                        "high",
                        "missing-zed-shared-mcp-edge",
                        f'.zpkg.toml must declare "{CANONICAL_ZED}" = "^0.1.0"',
                        ".zpkg.toml",
                    )
                )
            else:
                zed_declared = True
            build = zed.get("build")
            command = build.get("command") if isinstance(build, dict) else None
            if not isinstance(command, str) or "cargo build" not in command or "--locked" not in command:
                findings.append(
                    Finding(
                        "high",
                        "unlocked-zed-cargo-build",
                        "Zed build command must use cargo build --locked",
                        ".zpkg.toml",
                    )
                )

    lock_path = root / ".zpkg.lock"
    if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
        findings.append(
            Finding("high", "invalid-zed-lock", ".zpkg.lock must be a regular file", ".zpkg.lock")
        )
    elif not lock_path.is_file():
        findings.append(
            Finding(
                "high" if require_zed_lock else "medium",
                "missing-zed-lock",
                (
                    "frozen Zed resolution was required but .zpkg.lock is absent"
                    if require_zed_lock
                    else "Zed package edge is manifest-only; do not claim frozen resolution until .zpkg.lock exists"
                ),
                ".zpkg.lock",
            )
        )
    else:
        try:
            zed_lock = read_toml(lock_path)
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            findings.append(
                Finding("high", "invalid-zed-lock", ".zpkg.lock could not be parsed", ".zpkg.lock")
            )
        else:
            if not lock_has_resolution_payload(zed_lock):
                findings.append(
                    Finding(
                        "high" if require_zed_lock else "medium",
                        "empty-zed-lock",
                        (
                            "frozen Zed resolution was required but .zpkg.lock contains metadata only"
                            if require_zed_lock
                            else "Zed lock is a metadata-only placeholder; do not claim frozen resolution"
                        ),
                        ".zpkg.lock",
                    )
                )

    if dependencies and zed_declared and len(distinct_revisions) == 1:
        findings.append(
            Finding(
                "info",
                "shared-mcp-runtime-declared",
                "Cargo and Zed both declare the canonical shared MCP dependency",
            )
        )
    return sorted(findings, key=lambda item: (-RANK[item.severity], item.code, item.path or ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--require-zed-lock", action="store_true")
    parser.add_argument("--verify-revision-reachability", action="store_true")
    parser.add_argument("--fail-on", choices=RANK, default="high")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)

    findings = audit(
        args.repo_root.resolve(),
        require_zed_lock=args.require_zed_lock,
        verify_reachability=args.verify_revision_reachability,
    )
    report = {
        "schemaVersion": 1,
        "repositoryRoot": str(args.repo_root.resolve()),
        "zedLockRequired": args.require_zed_lock,
        "revisionReachabilityVerified": args.verify_revision_reachability,
        "summary": {level: sum(item.severity == level for item in findings) for level in RANK},
        "findings": [dataclasses.asdict(item) for item in findings],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    threshold = RANK[args.fail_on]
    return int(any(RANK[item.severity] >= threshold for item in findings))


if __name__ == "__main__":
    raise SystemExit(main())
