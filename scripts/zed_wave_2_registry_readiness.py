#!/usr/bin/env python3
"""Validate and probe the DEN-957 wave-2 recursive Zed package graph.

The probe is credential-free and treats HTTP 404 or no compatible 0.1.x
release as a publication-readiness state. Unexpected transport, status, schema,
graph, or credential-shape failures fail the workflow. This script does not
generate lockfiles and does not weaken the separate resolver/frozen-install
gates in the consumer repositories.
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
from pathlib import Path
from typing import Any

COORDINATE = re.compile(r"^[a-z0-9][a-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
COMPATIBLE_VERSION = re.compile(r"^0\.1\.\d+$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_ISSUES = {"DEN-2285", "DEN-2287", "DEN-2290", "DEN-2293"}
EXPECTED_TRANSITIVE_ONLY = {
    "shared-auth/shared-auth-interfaces",
    "shared-auth/shared-auth-lib",
}
EXPECTED_COUNTS = {
    "consumers": 4,
    "directPackages": 21,
    "transitiveOnlyPackages": 2,
    "recursivePackages": 23,
    "consumerDependencyEdges": 24,
    "packageDependencyEdges": 31,
    "totalDependencyEdges": 55,
}
CREDENTIAL_PREFIXES = (
    "gh" + "p_",
    "github" + "_pat_",
    "cf" + "at_",
    "lin" + "_api_",
    "AKIA",
)
ERROR_MESSAGE_LIMIT = 240


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


def safe_error_message(error: BaseException | str) -> str:
    message = " ".join(str(error).split())
    if any(prefix in message for prefix in CREDENTIAL_PREFIXES):
        return "credential-shaped diagnostic redacted"
    if len(message) <= ERROR_MESSAGE_LIMIT:
        return message
    return message[: ERROR_MESSAGE_LIMIT - 3] + "..."


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    for prefix in CREDENTIAL_PREFIXES:
        require(prefix not in serialized, f"credential-shaped value found in {path}")

    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(serialized, encoding="utf-8")
    temporary.replace(path)


def write_outputs(evidence: dict[str, Any]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    append_line(output_path, f"all_ready={str(evidence['allReady']).lower()}")
    append_line(output_path, f"ready_count={evidence['readyCount']}")
    append_line(output_path, f"blocked_count={evidence['blockedCount']}")
    append_line(output_path, f"probe_error_count={evidence['probeErrorCount']}")


def package_closure(
    roots: list[str], dependencies_by_package: dict[str, list[str]]
) -> set[str]:
    closure: set[str] = set()
    stack = list(reversed(roots))
    while stack:
        coordinate = stack.pop()
        if coordinate in closure:
            continue
        closure.add(coordinate)
        stack.extend(reversed(dependencies_by_package[coordinate]))
    return closure


def validate_acyclic(dependencies_by_package: dict[str, list[str]]) -> list[str]:
    state: dict[str, int] = {}
    order: list[str] = []
    stack: list[str] = []

    def visit(coordinate: str) -> None:
        status = state.get(coordinate, 0)
        if status == 2:
            return
        if status == 1:
            cycle_start = stack.index(coordinate)
            cycle = stack[cycle_start:] + [coordinate]
            raise RuntimeError("package dependency cycle: " + " -> ".join(cycle))
        state[coordinate] = 1
        stack.append(coordinate)
        for dependency in dependencies_by_package[coordinate]:
            visit(dependency)
        stack.pop()
        state[coordinate] = 2
        order.append(coordinate)

    for coordinate in sorted(dependencies_by_package):
        visit(coordinate)
    return order


def validate_manifest(
    manifest: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, list[str]],
    dict[str, list[str]],
    list[str],
]:
    require(manifest.get("schemaVersion") == 2, "schemaVersion must be 2")
    require(manifest.get("issue") == "DEN-957", "issue must be DEN-957")
    require(manifest.get("blockingIssue") == "DEN-3036", "blockingIssue must be DEN-3036")
    require(manifest.get("registry") == "https://registry.zpkg.net", "unexpected registry")
    require(manifest.get("requiredVersion") == "^0.1.0", "requiredVersion must be ^0.1.0")
    require(
        FULL_SHA.fullmatch(str(manifest.get("zedCliRevision", ""))) is not None,
        "zedCliRevision must be a full SHA",
    )
    require(manifest.get("counts") == EXPECTED_COUNTS, "declared graph counts drifted")

    packages = manifest.get("packages")
    consumers = manifest.get("consumers")
    require(isinstance(packages, list), "packages must be an array")
    require(isinstance(consumers, list), "consumers must be an array")
    require(len(packages) == EXPECTED_COUNTS["recursivePackages"], f"expected 23 packages, got {len(packages)}")
    require(len(consumers) == EXPECTED_COUNTS["consumers"], f"expected 4 consumers, got {len(consumers)}")

    package_by_coordinate: dict[str, dict[str, Any]] = {}
    dependencies_by_package: dict[str, list[str]] = {}
    for package in packages:
        require(isinstance(package, dict), "each package must be an object")
        coordinate = package.get("coordinate")
        source_repository = package.get("sourceRepository")
        visibility = package.get("sourceVisibility")
        dependencies = package.get("dependencies")
        require(
            isinstance(coordinate, str) and COORDINATE.fullmatch(coordinate) is not None,
            f"invalid coordinate: {coordinate}",
        )
        require(coordinate not in package_by_coordinate, f"duplicate package: {coordinate}")
        require(source_repository == coordinate, f"source repository must match coordinate: {coordinate}")
        require(visibility in {"public", "private"}, f"invalid source visibility: {coordinate}")
        require(isinstance(dependencies, list), f"dependencies must be an array: {coordinate}")
        require(
            all(isinstance(value, str) and COORDINATE.fullmatch(value) is not None for value in dependencies),
            f"invalid package dependency: {coordinate}",
        )
        require(len(set(dependencies)) == len(dependencies), f"duplicate dependency: {coordinate}")
        require(coordinate not in dependencies, f"self dependency: {coordinate}")
        package_by_coordinate[coordinate] = package
        dependencies_by_package[coordinate] = sorted(dependencies)

    package_coordinates = set(package_by_coordinate)
    for coordinate, dependencies in dependencies_by_package.items():
        unknown = set(dependencies) - package_coordinates
        require(not unknown, f"{coordinate} references unknown packages: {sorted(unknown)}")

    topological_order = validate_acyclic(dependencies_by_package)

    direct_by_consumer: dict[str, list[str]] = {}
    observed_issues: set[str] = set()
    direct_packages: set[str] = set()
    consumer_edges = 0
    for consumer in consumers:
        require(isinstance(consumer, dict), "each consumer must be an object")
        issue = consumer.get("issue")
        repository = consumer.get("repository")
        dependencies = consumer.get("dependencies")
        require(issue in EXPECTED_ISSUES, f"unexpected consumer issue: {issue}")
        require(issue not in observed_issues, f"duplicate consumer issue: {issue}")
        observed_issues.add(issue)
        require(
            isinstance(repository, str) and repository.count("/") == 1,
            f"invalid consumer repository: {repository}",
        )
        require(isinstance(dependencies, list) and len(dependencies) == 6, f"{issue} must declare six direct dependencies")
        require(len(set(dependencies)) == 6, f"{issue} direct dependencies must be unique")
        unknown = set(dependencies) - package_coordinates
        require(not unknown, f"{issue} references unknown packages: {sorted(unknown)}")
        direct_by_consumer[issue] = sorted(dependencies)
        direct_packages.update(dependencies)
        consumer_edges += len(dependencies)
    require(observed_issues == EXPECTED_ISSUES, "consumer issue set mismatch")

    transitive_only = package_coordinates - direct_packages
    package_edges = sum(len(values) for values in dependencies_by_package.values())
    computed_counts = {
        "consumers": len(consumers),
        "directPackages": len(direct_packages),
        "transitiveOnlyPackages": len(transitive_only),
        "recursivePackages": len(package_coordinates),
        "consumerDependencyEdges": consumer_edges,
        "packageDependencyEdges": package_edges,
        "totalDependencyEdges": consumer_edges + package_edges,
    }
    require(computed_counts == EXPECTED_COUNTS, f"computed graph counts drifted: {computed_counts}")
    require(transitive_only == EXPECTED_TRANSITIVE_ONLY, f"unexpected transitive-only package set: {sorted(transitive_only)}")

    closure_by_consumer = {
        issue: sorted(package_closure(dependencies, dependencies_by_package))
        for issue, dependencies in direct_by_consumer.items()
    }
    for issue, closure in closure_by_consumer.items():
        require(len(closure) == 8, f"{issue} recursive closure must contain eight packages")
        require(EXPECTED_TRANSITIVE_ONLY <= set(closure), f"{issue} is missing shared-auth transitive dependencies")

    return packages, consumers, dependencies_by_package, closure_by_consumer, topological_order


def probe_package(
    registry: str, package: dict[str, Any], requirement: str
) -> tuple[dict[str, Any], str | None]:
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
            "User-Agent": "ore-mcp-wave2-zed-readiness/2",
        },
    )
    item: dict[str, Any] = {
        "coordinate": coordinate,
        "sourceRepository": package["sourceRepository"],
        "sourceVisibility": package["sourceVisibility"],
        "dependencies": package["dependencies"],
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
            item.update({"state": "not-published", "compatibleVersions": []})
            return item, "not-published"
        item.update(
            {
                "state": "probe-error",
                "compatibleVersions": [],
                "error": {
                    "kind": "unexpected-http-status",
                    "message": f"unexpected HTTP {error.code}",
                },
            }
        )
        return item, "probe-error"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        item.update(
            {
                "state": "probe-error",
                "compatibleVersions": [],
                "error": {
                    "kind": "registry-transport",
                    "message": f"registry transport failed ({type(error).__name__})",
                },
            }
        )
        return item, "probe-error"
    except (json.JSONDecodeError, UnicodeError):
        item.update(
            {
                "state": "probe-error",
                "compatibleVersions": [],
                "error": {
                    "kind": "malformed-registry-json",
                    "message": "registry returned malformed JSON",
                },
            }
        )
        return item, "probe-error"

    try:
        require(isinstance(payload, dict), f"{coordinate}: registry payload must be an object")
        require(
            payload.get("org") == org and payload.get("name") == name,
            f"{coordinate}: registry identity mismatch",
        )
        versions = payload.get("versions", [])
        require(
            isinstance(versions, list)
            and all(isinstance(value, str) for value in versions),
            f"{coordinate}: versions must be a string array",
        )
    except RuntimeError as error:
        item.update(
            {
                "state": "probe-error",
                "compatibleVersions": [],
                "error": {
                    "kind": "invalid-registry-payload",
                    "message": safe_error_message(error),
                },
            }
        )
        return item, "probe-error"

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


def write_summary(evidence: dict[str, Any]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines = [
        "## DEN-957 wave-2 recursive Zed registry readiness",
        "",
        f"Registry: `{evidence['registry']}`",
        "",
        f"Published-compatible recursive packages: **{evidence['readyCount']} / {evidence['packageCount']}**",
        "",
        f"Direct packages: **{evidence['counts']['directPackages']}**; transitive-only packages: **{evidence['counts']['transitiveOnlyPackages']}**; total graph edges: **{evidence['counts']['totalDependencyEdges']}**.",
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

    if evidence["probeErrors"]:
        lines.extend(["", "### Probe failures", ""])
        for error in evidence["probeErrors"]:
            lines.append(
                f"- `{error['coordinate']}`: `{error['kind']}` — {error['message']}"
            )

    lines.extend(["", "### Consumer recursive gates", ""])
    for consumer in evidence["consumers"]:
        state = (
            "ready-for-resolver"
            if not consumer["blockedPackages"]
            else f"blocked ({len(consumer['blockedPackages'])} / {len(consumer['recursiveClosure'])})"
        )
        lines.append(
            f"- `{consumer['issue']}` / `{consumer['repository']}`: **{state}**"
        )

    lines.extend(
        [
            "",
            "This workflow is recursive publication-readiness evidence only. It does not generate or approve `.zpkg.lock`, and it does not count as a clean-clone frozen install. Each consumer must still pass its exact resolver and isolated frozen-replay gate.",
        ]
    )
    append_line(summary_path, "\n".join(lines))


def run(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "manifest root must be an object")
    packages, consumers, dependencies_by_package, closure_by_consumer, topological_order = validate_manifest(manifest)

    registry = manifest["registry"].rstrip("/")
    requirement = manifest["requiredVersion"]
    evidence: dict[str, Any] = {
        "schemaVersion": 2,
        "issue": manifest["issue"],
        "blockingIssue": manifest["blockingIssue"],
        "phase": manifest["phase"],
        "observedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "registry": registry,
        "requiredVersion": requirement,
        "zedCliRevision": manifest["zedCliRevision"],
        "qualification": manifest["qualification"],
        "counts": manifest["counts"],
        "packageCount": len(packages),
        "readyCount": 0,
        "blockedCount": 0,
        "probeErrorCount": 0,
        "allReady": False,
        "topologicalOrder": topological_order,
        "packages": [],
        "consumers": [],
        "blocked": [],
        "probeErrors": [],
    }

    for package in sorted(packages, key=lambda item: item["coordinate"]):
        try:
            item, blocked_reason = probe_package(registry, package, requirement)
        except Exception as error:
            coordinate = package["coordinate"]
            org, name = coordinate.split("/", 1)
            item = {
                "coordinate": coordinate,
                "sourceRepository": package["sourceRepository"],
                "sourceVisibility": package["sourceVisibility"],
                "dependencies": package["dependencies"],
                "requirement": requirement,
                "url": (
                    f"{registry}/v1/packages/"
                    f"{urllib.parse.quote(org, safe='')}/{urllib.parse.quote(name, safe='')}"
                ),
                "state": "probe-error",
                "compatibleVersions": [],
                "error": {
                    "kind": "unexpected-probe-error",
                    "message": safe_error_message(error),
                },
            }
            blocked_reason = "probe-error"
        evidence["packages"].append(item)
        if blocked_reason:
            evidence["blocked"].append(
                {"coordinate": item["coordinate"], "reason": blocked_reason}
            )
        if item["state"] == "probe-error":
            evidence["probeErrors"].append(
                {"coordinate": item["coordinate"], **item["error"]}
            )

    package_states = {
        item["coordinate"]: item["state"] for item in evidence["packages"]
    }
    consumer_by_issue = {consumer["issue"]: consumer for consumer in consumers}
    for issue in sorted(closure_by_consumer):
        consumer = consumer_by_issue[issue]
        closure = closure_by_consumer[issue]
        blocked = [coordinate for coordinate in closure if package_states[coordinate] != "ready"]
        evidence["consumers"].append(
            {
                "issue": issue,
                "repository": consumer["repository"],
                "directDependencies": consumer["dependencies"],
                "recursiveClosure": closure,
                "blockedPackages": blocked,
                "readyForResolver": not blocked,
            }
        )

    evidence["readyCount"] = sum(
        item["state"] == "ready" for item in evidence["packages"]
    )
    evidence["blockedCount"] = len(evidence["blocked"])
    evidence["probeErrorCount"] = len(evidence["probeErrors"])
    evidence["allReady"] = (
        evidence["blockedCount"] == 0 and evidence["probeErrorCount"] == 0
    )
    evidence["status"] = "failed" if evidence["probeErrors"] else "complete"

    write_evidence(args.evidence, evidence)
    write_outputs(evidence)
    write_summary(evidence)
    print(
        f"registry probe completed: {evidence['readyCount']} ready, "
        f"{evidence['blockedCount']} blocked, {evidence['probeErrorCount']} probe errors, "
        f"{evidence['packageCount']} recursive packages"
    )
    for error in evidence["probeErrors"]:
        print(
            f"error: {error['coordinate']}: {error['kind']}: {error['message']}",
            file=sys.stderr,
        )
    return 1 if evidence["probeErrors"] else 0


def setup_failure_evidence(error: BaseException) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "issue": "DEN-957",
        "blockingIssue": "DEN-3036",
        "observedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "failed",
        "packageCount": 0,
        "readyCount": 0,
        "blockedCount": 0,
        "probeErrorCount": 1,
        "allReady": False,
        "packages": [],
        "consumers": [],
        "blocked": [],
        "probeErrors": [
            {
                "coordinate": "<probe-setup>",
                "kind": "probe-setup-error",
                "message": safe_error_message(error),
            }
        ],
    }


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except Exception as error:
        evidence = setup_failure_evidence(error)
        write_evidence(args.evidence, evidence)
        write_outputs(evidence)
        print(f"error: {safe_error_message(error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
