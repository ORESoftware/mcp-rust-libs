#!/usr/bin/env python3
"""Validate immutable GitHub pull-request evidence for the Rust MCP fleet.

The default mode is deterministic and offline: it validates the evidence schema
and cross-checks the listed servers against ``fleet/inventory.json``.

``--live`` additionally queries GitHub's public pull-request API and fails when
a PR's purpose, head SHA, merge SHA, draft state, or merged/open state has
drifted. No token is required for the bounded public fleet. Operators may set
``MCP_FLEET_GITHUB_TOKEN`` to a short-lived GitHub App installation token when
private repositories are added.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping

MAX_API_BYTES = 1_048_576
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_STATES = frozenset(
    {"merged", "open_draft", "open_ready", "closed_unmerged"}
)
SERVER_PURPOSE = "server-hardening"
SHARED_PURPOSE = "fleet-audit"


class EvidenceError(ValueError):
    """Raised when committed or live fleet evidence violates the contract."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect refused: {msg}", headers, fp
        )


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"{path} is not valid JSON: {exc}") from exc


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{label} must be a non-empty string")
    return value


def _validate_entry(
    raw: Any,
    *,
    label: str,
    expected_purpose: str,
    inventory_repositories: frozenset[str],
) -> dict[str, Any]:
    entry = _require_dict(raw, label)
    allowed_keys = {
        "repository",
        "pullRequest",
        "purpose",
        "expectedState",
        "expectedHeadSha",
        "expectedMergeSha",
        "titleMustContainAny",
        "linear",
        "note",
    }
    unknown = sorted(set(entry) - allowed_keys)
    if unknown:
        raise EvidenceError(f"{label} has unknown keys: {', '.join(unknown)}")

    repository = _require_nonempty_string(
        entry.get("repository"), f"{label}.repository"
    )
    if not REPOSITORY_RE.fullmatch(repository):
        raise EvidenceError(f"{label}.repository is not owner/name: {repository!r}")
    if repository not in inventory_repositories:
        raise EvidenceError(
            f"{label}.repository is not present in fleet/inventory.json: {repository}"
        )

    pull_request = entry.get("pullRequest")
    if (
        not isinstance(pull_request, int)
        or isinstance(pull_request, bool)
        or pull_request <= 0
    ):
        raise EvidenceError(f"{label}.pullRequest must be a positive integer")

    purpose = _require_nonempty_string(entry.get("purpose"), f"{label}.purpose")
    if purpose != expected_purpose:
        raise EvidenceError(
            f"{label}.purpose must be {expected_purpose!r}, got {purpose!r}"
        )

    expected_state = _require_nonempty_string(
        entry.get("expectedState"), f"{label}.expectedState"
    )
    if expected_state not in EXPECTED_STATES:
        raise EvidenceError(
            f"{label}.expectedState must be one of {sorted(EXPECTED_STATES)}"
        )

    expected_head = _require_nonempty_string(
        entry.get("expectedHeadSha"), f"{label}.expectedHeadSha"
    )
    if not SHA_RE.fullmatch(expected_head):
        raise EvidenceError(
            f"{label}.expectedHeadSha must be exactly 40 lowercase hex characters"
        )

    expected_merge = entry.get("expectedMergeSha")
    if expected_state == "merged":
        expected_merge = _require_nonempty_string(
            expected_merge, f"{label}.expectedMergeSha"
        )
        if not SHA_RE.fullmatch(expected_merge):
            raise EvidenceError(
                f"{label}.expectedMergeSha must be exactly 40 lowercase hex characters"
            )
    elif expected_merge is not None:
        raise EvidenceError(
            f"{label}.expectedMergeSha is only allowed for merged evidence"
        )

    title_terms = entry.get("titleMustContainAny")
    if not isinstance(title_terms, list) or not title_terms:
        raise EvidenceError(f"{label}.titleMustContainAny must be a non-empty list")
    normalized_terms: list[str] = []
    for index, term in enumerate(title_terms):
        text = _require_nonempty_string(
            term, f"{label}.titleMustContainAny[{index}]"
        ).strip().lower()
        if len(text) > 80:
            raise EvidenceError(
                f"{label}.titleMustContainAny[{index}] exceeds 80 characters"
            )
        normalized_terms.append(text)
    if len(set(normalized_terms)) != len(normalized_terms):
        raise EvidenceError(f"{label}.titleMustContainAny contains duplicates")

    linear = entry.get("linear")
    if linear is not None:
        linear_text = _require_nonempty_string(linear, f"{label}.linear")
        if not re.fullmatch(r"DEN-[1-9][0-9]*", linear_text):
            raise EvidenceError(f"{label}.linear must use the DEN-123 form")

    return entry


def validate_document(
    evidence: Any, inventory: Any
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate committed evidence and return server entries plus shared core."""

    doc = _require_dict(evidence, "evidence")
    if doc.get("schemaVersion") != 1:
        raise EvidenceError("evidence.schemaVersion must equal 1")
    _require_nonempty_string(doc.get("asOf"), "evidence.asOf")
    _require_nonempty_string(doc.get("scope"), "evidence.scope")

    inventory_doc = _require_dict(inventory, "inventory")
    existing = inventory_doc.get("existing")
    if not isinstance(existing, list) or not all(
        isinstance(item, str) for item in existing
    ):
        raise EvidenceError("inventory.existing must be a string list")
    shared_repository = _require_nonempty_string(
        inventory_doc.get("sharedRepository"), "inventory.sharedRepository"
    )
    inventory_repositories = frozenset([*existing, shared_repository])

    servers_raw = doc.get("servers")
    if not isinstance(servers_raw, list):
        raise EvidenceError("evidence.servers must be a list")
    expected_count = doc.get("expectedServerCount")
    if (
        not isinstance(expected_count, int)
        or isinstance(expected_count, bool)
        or expected_count <= 0
    ):
        raise EvidenceError("evidence.expectedServerCount must be a positive integer")
    if len(servers_raw) != expected_count:
        raise EvidenceError(
            "evidence.servers count does not match expectedServerCount: "
            f"{len(servers_raw)} != {expected_count}"
        )

    servers = [
        _validate_entry(
            raw,
            label=f"evidence.servers[{index}]",
            expected_purpose=SERVER_PURPOSE,
            inventory_repositories=inventory_repositories,
        )
        for index, raw in enumerate(servers_raw)
    ]
    shared_core = _validate_entry(
        doc.get("sharedCore"),
        label="evidence.sharedCore",
        expected_purpose=SHARED_PURPOSE,
        inventory_repositories=inventory_repositories,
    )
    if shared_core["repository"] != shared_repository:
        raise EvidenceError(
            "evidence.sharedCore.repository must equal inventory.sharedRepository"
        )

    identities: set[tuple[str, int]] = set()
    repositories: set[str] = set()
    for label, entry in [
        *((f"evidence.servers[{i}]", value) for i, value in enumerate(servers)),
        ("evidence.sharedCore", shared_core),
    ]:
        identity = (entry["repository"], entry["pullRequest"])
        if identity in identities:
            raise EvidenceError(f"duplicate PR evidence at {label}: {identity}")
        identities.add(identity)
        if entry["repository"] in repositories:
            raise EvidenceError(
                f"repository appears more than once in the batch: {entry['repository']}"
            )
        repositories.add(entry["repository"])

    return servers, shared_core


def normalized_pull_state(payload: Mapping[str, Any]) -> str:
    if payload.get("merged_at"):
        return "merged"
    state = payload.get("state")
    if state == "open":
        return "open_draft" if payload.get("draft") is True else "open_ready"
    if state == "closed":
        return "closed_unmerged"
    raise EvidenceError(f"GitHub returned an unknown pull-request state: {state!r}")


def validate_live_pull(entry: Mapping[str, Any], payload: Any) -> None:
    """Validate one GitHub REST pull-request payload against committed evidence."""

    pull = _require_dict(payload, "GitHub pull request")
    actual_number = pull.get("number")
    if actual_number != entry["pullRequest"]:
        raise EvidenceError(
            f"{entry['repository']} expected PR #{entry['pullRequest']}, "
            f"GitHub returned #{actual_number}"
        )

    base_repo = (
        pull.get("base", {}).get("repo", {}).get("full_name")
        if isinstance(pull.get("base"), dict)
        else None
    )
    if base_repo != entry["repository"]:
        raise EvidenceError(
            f"{entry['repository']} PR #{entry['pullRequest']} belongs to "
            f"{base_repo!r}, not the recorded repository"
        )

    title = _require_nonempty_string(
        pull.get("title"),
        f"{entry['repository']} PR #{entry['pullRequest']} title",
    )
    lowered_title = title.lower()
    if not any(term.lower() in lowered_title for term in entry["titleMustContainAny"]):
        raise EvidenceError(
            f"{entry['repository']} PR #{entry['pullRequest']} title no longer "
            f"matches its recorded purpose: {title!r}"
        )

    head_sha = (
        pull.get("head", {}).get("sha")
        if isinstance(pull.get("head"), dict)
        else None
    )
    if head_sha != entry["expectedHeadSha"]:
        raise EvidenceError(
            f"{entry['repository']} PR #{entry['pullRequest']} head drifted: "
            f"{head_sha!r} != {entry['expectedHeadSha']}"
        )

    actual_state = normalized_pull_state(pull)
    if actual_state != entry["expectedState"]:
        raise EvidenceError(
            f"{entry['repository']} PR #{entry['pullRequest']} state drifted: "
            f"{actual_state} != {entry['expectedState']}"
        )

    if entry["expectedState"] == "merged":
        merge_sha = pull.get("merge_commit_sha")
        if merge_sha != entry["expectedMergeSha"]:
            raise EvidenceError(
                f"{entry['repository']} PR #{entry['pullRequest']} merge SHA drifted: "
                f"{merge_sha!r} != {entry['expectedMergeSha']}"
            )


def _fetch_pull(
    repository: str,
    pull_request: int,
    *,
    token: str | None,
    opener: Any | None = None,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repository}/pulls/{pull_request}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "mcp-rust-libs-fleet-evidence/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    http = opener or urllib.request.build_opener(_NoRedirect())
    try:
        with http.open(request, timeout=10) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise EvidenceError(f"GitHub returned HTTP {status} for {url}")
            raw = response.read(MAX_API_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise EvidenceError(f"GitHub returned HTTP {exc.code} for {url}") from exc
    except urllib.error.URLError as exc:
        raise EvidenceError(f"GitHub request failed for {url}: {exc.reason}") from exc
    if len(raw) > MAX_API_BYTES:
        raise EvidenceError(f"GitHub response exceeded {MAX_API_BYTES} bytes for {url}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"GitHub returned invalid JSON for {url}: {exc}") from exc
    return _require_dict(payload, f"GitHub response for {url}")


def iter_entries(
    servers: Iterable[dict[str, Any]], shared_core: dict[str, Any]
) -> Iterable[dict[str, Any]]:
    yield from servers
    yield shared_core


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        default=Path("fleet/pr-evidence.json"),
        help="committed fleet PR evidence JSON",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("fleet/inventory.json"),
        help="fleet repository inventory JSON",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="query GitHub and compare current PR state/head/title/merge evidence",
    )
    parser.add_argument(
        "--token-env",
        default="MCP_FLEET_GITHUB_TOKEN",
        help="optional environment variable holding a short-lived GitHub App token",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        evidence = _load_json(args.evidence)
        inventory = _load_json(args.inventory)
        servers, shared_core = validate_document(evidence, inventory)
        entries = list(iter_entries(servers, shared_core))
        if args.live:
            token = os.environ.get(args.token_env) or None
            for entry in entries:
                payload = _fetch_pull(
                    entry["repository"], entry["pullRequest"], token=token
                )
                validate_live_pull(entry, payload)
        mode = "live" if args.live else "offline"
        print(
            f"fleet PR evidence valid ({mode}): "
            f"{len(servers)} servers + shared core"
        )
        return 0
    except EvidenceError as exc:
        print(f"fleet PR evidence invalid: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
