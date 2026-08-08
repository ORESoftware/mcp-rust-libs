#!/usr/bin/env python3
"""Validate and probe the DEN-957 wave-2 Zed package publication graph.

The probe is credential-free and treats HTTP 404 or no compatible 0.1.x
release as a publication-readiness state. Unexpected transport/status/schema
errors fail the workflow. This script does not generate lockfiles and does not
weaken the separate resolver/frozen-install gates in the consumer repositories.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

COORDINATE = re.compile(r"^[a-z0-9][a-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
COMPATIBLE_VERSION = re.compile(r"^0\.1\.\d+$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
CREDENTIAL_PREFIXES = (
    "gh" + "p_",
    "github" + "_pat_",
    "cf" + "at_",
    "lin" + "_api_",
    "AKIA",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    return parser.parse_args()


def append_line(path: str | None, line: str) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(line)
        stream.write("\n")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_manifest(manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    require(manifest.get("schemaVersion") == 1, "schemaVersion must be 1")
    require(manifest.get("issue") == "DEN-957", "issue must be DEN-957")
    require(manifest.get("registry") == "https://registry.zpkg.net", "unexpected registry")
    require(manifest.get("requiredVersion") == "^0.1.0", "requiredVersion must be ^0.1.0")
    require(FULL_SHA.fullmatch(str(manifest.get("zedCliRevision", ""))) is not None, "zedCliRevision must be a full SHA")

    packages = manifest.get("packages")
    consumers = manifest.get("consumers")
    require(isinstance(packages, list), "packages must be an array")
    require(isinstance(consumers, list), "consumers must be an array")
    require(len(packages) == 21, f"expected 21 packages, got {len(packages)}")
    require(len(consumers) == 4, f"expected 4 consumers, got {len(consumers)}")

    package_coordinates: list[str] = []
    for package in packages:
        require(isinstance(package, dict), "each package must be an object")
        coordinate = package.get("coordinate")
        source_repository = package.get("sourceRepository")
        visibility = package.get("sourceVisibility")
        require(isinstance(coordinate, str) and COORDINATE.fullmatch(coordinate) is not None, f"invalid coordinate: {coordinate}")
        require(source_repository == coordinate, f"source repository must match coordinate: {coordinate}")
        require(visibility in {"public", "private"}, f"invalid source visibility: {coordinate}")
        package_coordinates.append(coordinate)
    require(len(set(package_coordinates)) == 21, "package coordinates must be unique")

    referenced: list[str] = []
    expected_issues = {"DEN-2285", "DEN-2287", "DEN-2290", "DEN-2293"}
    observed_issues: set[str] = set()
    for consumer in consumers:
        require(isinstance(consumer, dict), "each consumer must be an object")
        issue = consumer.get("issue")
        repository = consumer.get("repository")
        dependencies = consumer.get("dependencies")
        require(issue in expected_issues, f"unexpected consumer issue: {issue}")
        require(issue not in observed_issues, f"duplicate consumer issue: {issue}")
        observed_issues.add(issue)
        require(isinstance(repository, str) and repository.count("/") == 1, f"invalid consumer repository: {repository}")
        require(isinstance(dependencies, list) and len(dependencies) == 6, f"{issue} must declare six dependencies")
        require(len(set(dependencies)) == 6, f"{issue} dependencies must be unique")
        for dependency in dependencies:
            require(dependency in package_coordinates, f"{issue} references unknown package: {dependency}")
            referenced.append(dependency)
    require(observed_issues == expected_issues, "consumer issue set mismatch")

    counts = Counter(referenced)
    require(counts["shared-auth/shared-auth-clients"] == 4, "shared-auth client must be shared by all four consumers")
    for coordinate in package_coordinates:
        expected_count = 4 if coordinate == "shared-auth/shared-auth-clients" else 1
        require(counts[coordinate] == expected_count, f"unexpected consumer reference count for {coordinate}")

    return packages, consumers


def probe_package(registry: str, package: dict[str, Any], requirement: str) -> tuple[dict[str, Any], str | None]:
    coordinate = package["coordinate"]
    org, name = coordinate.split("/", 1)
    url = (
        f"{registry.rstrip('/')}/v1/packages/"
        f"{urllib.parse.quote(org, safe='')}/{urllib.parse.quote(name, safe='')}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "ore-mcp-wave2-zed-readiness/1",
        },
    )
    item: dict[str, Any] = {
        "coordinate": coordinate,
        "sourceRepository": package["sourceRepository"],
        "sourceVisibility": package["sourceVisibility"],
        "requirement": requirement,
        "url": url,
    }

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            item["httpStatus"] = response.status
            require(response.status == 200, f"{coordinate}: unexpected HTTP {response.status}")
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        item["httpStatus"] = error.code
        if error.code == 404:
            item.update(
                {
                    "state": "not-published",
                    "compatibleVersions": [],
                }
            )
            return item, "not-published"
        raise RuntimeError(f"{coordinate}: unexpected HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError(
            f"{coordinate}: registry transport failed ({type(error).__name__})"
        ) from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{coordinate}: registry returned malformed JSON") from error

    require(isinstance(payload, dict), f"{coordinate}: registry payload must be an object")
    require(payload.get("org") == org and payload.get("name") == name, f"{coordinate}: registry identity mismatch")
    versions = payload.get("versions", [])
    require(
        isinstance(versions, list) and all(isinstance(value, str) for value in versions),
        f"{coordinate}: versions must be a string array",
    )
    compatible = sorted(value for value in versions if COMPATIBLE_VERSION.fullmatch(value))
    item.update(
        {
            "state": "ready" if compatible else "no-compatible-version",
            "latest": payload.get("latest"),
            "versions": sorted(versions),
            "compatibleVersions": compatible,
        }
    )
    return item, None if compatible else "no-compatible-version"


def write_summary(evidence: dict[str, Any], consumers: list[dict[str, Any]]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## DEN-957 wave-2 Zed registry readiness",
        "",
        f"Registry: `{evidence['registry']}`",
        "",
        f"Published-compatible packages: **{evidence['readyCount']} / {evidence['packageCount']}**",
        "",
        "| Package | Source | HTTP | State | Compatible versions |",
        "|---|---|---:|---|---|",
    ]
    for package in evidence["packages"]:
        versions = ", ".join(package.get("compatibleVersions", [])) or "—"
        lines.append(
            f"| `{package['coordinate']}` | `{package['sourceRepository']}` | "
            f"{package.get('httpStatus', '—')} | `{package['state']}` | {versions} |"
        )

    lines.extend(["", "### Consumer gates", ""])
    package_states = {item["coordinate"]: item["state"] for item in evidence["packages"]}
    for consumer in consumers:
        blocked = [
            dependency
            for dependency in consumer["dependencies"]
            if package_states[dependency] != "ready"
        ]
        state = "ready-for-resolver" if not blocked else f"blocked ({len(blocked)})"
        lines.append(f"- `{consumer['issue']}` / `{consumer['repository']}`: **{state}**")

    lines.extend(
        [
            "",
            "This workflow is publication-readiness evidence only. It does not generate or approve `.zpkg.lock`, and it does not count as a clean-clone frozen install. Each consumer must still pass its exact resolver and isolated frozen-replay gate.",
        ]
    )
    append_line(summary_path, "\n".join(lines))


def main() -> int:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "manifest root must be an object")
    packages, consumers = validate_manifest(manifest)

    registry = manifest["registry"].rstrip("/")
    requirement = manifest["requiredVersion"]
    evidence: dict[str, Any] = {
        "schemaVersion": 1,
        "issue": manifest["issue"],
        "phase": manifest["phase"],
        "observedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "registry": registry,
        "requiredVersion": requirement,
        "zedCliRevision": manifest["zedCliRevision"],
        "qualification": manifest["qualification"],
        "packageCount": len(packages),
        "readyCount": 0,
        "blockedCount": 0,
        "allReady": False,
        "packages": [],
        "blocked": [],
    }

    for package in sorted(packages, key=lambda item: item["coordinate"]):
        item, blocked_reason = probe_package(registry, package, requirement)
        evidence["packages"].append(item)
        if blocked_reason:
            evidence["blocked"].append(
                {"coordinate": item["coordinate"], "reason": blocked_reason}
            )

    evidence["readyCount"] = sum(
        item["state"] == "ready" for item in evidence["packages"]
    )
    evidence["blockedCount"] = len(evidence["blocked"])
    evidence["allReady"] = evidence["blockedCount"] == 0

    args.evidence.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    serialized = args.evidence.read_text(encoding="utf-8")
    for prefix in CREDENTIAL_PREFIXES:
        require(prefix not in serialized, f"credential-shaped value found in {args.evidence}")

    append_line(os.environ.get("GITHUB_OUTPUT"), f"all_ready={str(evidence['allReady']).lower()}")
    append_line(os.environ.get("GITHUB_OUTPUT"), f"ready_count={evidence['readyCount']}")
    append_line(os.environ.get("GITHUB_OUTPUT"), f"blocked_count={evidence['blockedCount']}")
    write_summary(evidence, consumers)
    print(
        f"registry probe completed: {evidence['readyCount']} ready, "
        f"{evidence['blockedCount']} blocked, {evidence['packageCount']} total"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
