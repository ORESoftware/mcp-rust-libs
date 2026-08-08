#!/usr/bin/env python3
"""Fail-closed validation for DEN-957 wave-2 runtime evidence.

The validator keeps three evidence classes separate:

* production official-rmcp runtime completion;
* independent matching test-organization runtime provenance; and
* still-incomplete Zed registry, resolver-lock, and frozen-install evidence.

It intentionally validates exact repositories, revisions, run counts, operating
systems, toolchains, and blocker state so a stale or over-claimed fleet ledger
cannot silently pass review.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WAVE = ROOT / "fleet/modularization-wave-2-zed-graph.json"
DEFAULT_PROVENANCE = (
    ROOT / "fleet/modularization-wave-2-runtime-test-org-provenance.json"
)

SHA40 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_SHARED_REVISION = "458419497de273d2ca6089a727f38894083d8da6"
EXPECTED_OS = {"ubuntu-24.04", "macos-14", "windows-2022"}
EXPECTED_TOOLCHAINS = {"1.88.0", "1.97.1"}
EXPECTED_CONSUMERS = {
    "apostille-me/apme-mcp-server.rs",
    "embedded-alerts/eal-mcp-server.rs",
    "evento-globolo/evgl-mcp-server.rs",
    "hacker-house-medellin/hhm-mcp-server.rs",
}
EXPECTED_COMPLETE_TEST_ORGS = {
    "embedded-alerts/eal-mcp-server.rs",
    "evento-globolo/evgl-mcp-server.rs",
}
EXPECTED_BLOCKED_TEST_ORGS = {
    "apostille-me/apme-mcp-server.rs",
    "hacker-house-medellin/hhm-mcp-server.rs",
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def is_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA40.fullmatch(value) is not None


def is_positive_run(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def require_matrix(record: dict[str, Any], path: str, errors: list[str]) -> None:
    require(record.get("matrixJobs") == 6, f"{path}.matrixJobs must equal 6", errors)
    require(
        set(record.get("operatingSystems", [])) == EXPECTED_OS,
        f"{path}.operatingSystems must be the reviewed Linux/macOS/Windows set",
        errors,
    )
    require(
        set(record.get("toolchains", [])) == EXPECTED_TOOLCHAINS,
        f"{path}.toolchains must be Rust 1.88.0 and 1.97.1",
        errors,
    )


def validate_wave(wave: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(wave.get("schemaVersion") == 3, "wave schemaVersion must equal 3", errors)
    require(
        wave.get("wave") == "zed-graph-mcp-wave-2",
        "wave identifier is incorrect",
        errors,
    )

    protocol = wave.get("protocolPolicy", {})
    require(
        protocol.get("productionFinal") == "2025-11-25",
        "production final protocol must be 2025-11-25",
        errors,
    )
    require(
        protocol.get("preview") == "2026-07-28",
        "preview protocol must remain explicitly recorded",
        errors,
    )
    require(
        protocol.get("previewEnabled") is False,
        "preview protocol must remain disabled",
        errors,
    )
    require(
        protocol.get("rejectedLegacy") == ["2025-06-18"],
        "legacy rejection set must contain exactly 2025-06-18",
        errors,
    )
    require(
        protocol.get("dispatchPolicy") == "official-rmcp",
        "dispatch policy must be official-rmcp",
        errors,
    )
    require(
        protocol.get("sdkVersion") == "2.2.0",
        "reviewed rmcp version must be 2.2.0",
        errors,
    )
    require(
        protocol.get("sharedRuntimeRevision") == EXPECTED_SHARED_REVISION,
        "shared runtime revision is stale or unexpected",
        errors,
    )
    require(
        protocol.get("runtimeMigrationComplete") is True,
        "runtime migration must be recorded complete",
        errors,
    )

    exact = wave.get("exactProtocolAdapter", {})
    require(exact.get("complete") is True, "exact protocol adapter must be complete", errors)
    require(exact.get("pullRequest") == 23, "exact protocol adapter PR must be #23", errors)
    require(is_sha(exact.get("exactHead")), "exact protocol head must be a full SHA", errors)
    require(
        exact.get("mergeRevision") == EXPECTED_SHARED_REVISION,
        "exact protocol merge revision must match the consumer pin",
        errors,
    )
    require(
        is_positive_run(exact.get("exactHeadCiRun")),
        "exact protocol adapter CI run is missing",
        errors,
    )

    graph = wave.get("sharedGraphContract", {})
    require(graph.get("complete") is True, "shared graph contract must be complete", errors)
    require(graph.get("pullRequest") == 17, "shared graph contract PR must be #17", errors)
    require(is_sha(graph.get("mergeRevision")), "graph merge revision must be a full SHA", errors)
    require(
        is_positive_run(graph.get("exactHeadCiRun")),
        "graph contract CI run is missing",
        errors,
    )

    process = wave.get("sharedProcessConsumerProof", {})
    require(process.get("complete") is True, "shared process proof must be complete", errors)
    require(is_sha(process.get("exactHead")), "process proof head must be a full SHA", errors)
    require(is_sha(process.get("mergeCommit")), "process proof merge must be a full SHA", errors)
    runs = process.get("workflowRuns", [])
    require(
        isinstance(runs, list) and len(runs) == 2 and all(is_positive_run(run) for run in runs),
        "process proof must record two positive workflow runs",
        errors,
    )
    require_matrix(process, "sharedProcessConsumerProof", errors)

    consumers = wave.get("consumers", [])
    require(isinstance(consumers, list), "consumers must be a list", errors)
    by_repository = {
        consumer.get("repository"): consumer
        for consumer in consumers
        if isinstance(consumer, dict)
    }
    require(
        set(by_repository) == EXPECTED_CONSUMERS,
        "wave must contain exactly the four reviewed consumer repositories",
        errors,
    )

    for repository in sorted(EXPECTED_CONSUMERS):
        consumer = by_repository.get(repository, {})
        prefix = f"consumers[{repository}]"
        phase_a = consumer.get("phaseA", {})
        require(phase_a.get("complete") is True, f"{prefix}.phaseA is incomplete", errors)
        require(
            phase_a.get("rustLockPresent") is True,
            f"{prefix}.phaseA Rust lock is missing",
            errors,
        )
        require(is_sha(phase_a.get("mergeCommit")), f"{prefix}.phaseA merge SHA is invalid", errors)
        require(
            is_positive_run(phase_a.get("exactHeadCiRun")),
            f"{prefix}.phaseA CI run is missing",
            errors,
        )

        runtime = consumer.get("runtime", {})
        for key in (
            "complete",
            "exactProtocol",
            "previewRejected",
            "realProcessConformance",
            "stdoutProtocolPure",
        ):
            require(runtime.get(key) is True, f"{prefix}.runtime.{key} must be true", errors)
        require(
            runtime.get("legacyRejected") == ["2025-06-18"],
            f"{prefix}.runtime legacy rejection is incomplete",
            errors,
        )
        require(
            runtime.get("sharedRevision") == EXPECTED_SHARED_REVISION,
            f"{prefix}.runtime shared revision is stale",
            errors,
        )
        require(
            runtime.get("rmcpVersion") == "2.2.0",
            f"{prefix}.runtime rmcp version is not exact 2.2.0",
            errors,
        )
        require(
            runtime.get("protocolVersion") == "2025-11-25",
            f"{prefix}.runtime protocol is not final 2025-11-25",
            errors,
        )
        require(is_sha(runtime.get("exactHead")), f"{prefix}.runtime head SHA is invalid", errors)
        require(is_sha(runtime.get("mergeCommit")), f"{prefix}.runtime merge SHA is invalid", errors)
        runtime_runs = runtime.get("workflowRuns", [])
        require(
            isinstance(runtime_runs, list)
            and len(runtime_runs) == 2
            and all(is_positive_run(run) for run in runtime_runs),
            f"{prefix}.runtime must record two positive exact-head runs",
            errors,
        )

        zed = consumer.get("zed", {})
        require(zed.get("lockPresent") is False, f"{prefix} falsely claims a Zed lock", errors)
        require(
            zed.get("frozenInstall") is False,
            f"{prefix} falsely claims frozen Zed installation",
            errors,
        )
        require(zed.get("blocker") == "DEN-3036", f"{prefix} Zed blocker is incorrect", errors)

        test_org = consumer.get("testOrganization", {})
        if repository in EXPECTED_COMPLETE_TEST_ORGS:
            require(
                test_org.get("status") == "complete-interim",
                f"{prefix} test-org status must be complete-interim",
                errors,
            )
            require(
                test_org.get("connectedRepository") is True,
                f"{prefix} test repository must be connected",
                errors,
            )
            require(
                test_org.get("dedicatedRepository") is False,
                f"{prefix} must not over-claim a dedicated test repository",
                errors,
            )
            require(
                test_org.get("qualification") == "exact-source-runtime-provenance",
                f"{prefix} test qualification is incorrect",
                errors,
            )
            require(is_sha(test_org.get("exactHead")), f"{prefix} test head SHA is invalid", errors)
            require(is_sha(test_org.get("mergeCommit")), f"{prefix} test merge SHA is invalid", errors)
            require(
                is_positive_run(test_org.get("workflowRun")),
                f"{prefix} test workflow run is missing",
                errors,
            )
            require_matrix(test_org, f"{prefix}.testOrganization", errors)
        else:
            require(
                test_org.get("status") == "blocked-dedicated-repository",
                f"{prefix} test-org blocker status is incorrect",
                errors,
            )
            require(
                test_org.get("connectedRepository") is False,
                f"{prefix} falsely claims a connected test repository",
                errors,
            )
            require(
                test_org.get("dedicatedRepository") is False,
                f"{prefix} falsely claims a dedicated test repository",
                errors,
            )
            require(
                test_org.get("followUpLinear") == "DEN-3060",
                f"{prefix} test-org Linear follow-up is incorrect",
                errors,
            )
            require(
                test_org.get("followUpGitHub") == "ORESoftware/mcp-rust-libs#27",
                f"{prefix} test-org GitHub follow-up is incorrect",
                errors,
            )

    closure = wave.get("publicationClosure", {})
    require(closure.get("linear") == "DEN-3036", "publication blocker must be DEN-3036", errors)
    require(closure.get("readyPackages") == 0, "publication readiness must remain 0", errors)
    require(closure.get("totalPackages") == 23, "publication closure must contain 23 packages", errors)
    require(
        closure.get("allBlockedByHttp404") is True,
        "publication closure must record the reviewed HTTP 404 blocker",
        errors,
    )
    return errors


def validate_provenance(provenance: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(
        provenance.get("schemaVersion") == 1,
        "runtime provenance schemaVersion must equal 1",
        errors,
    )
    require(
        provenance.get("sharedRuntimeRevision") == EXPECTED_SHARED_REVISION,
        "runtime provenance shared revision is stale",
        errors,
    )

    security = provenance.get("securityModel", {})
    require(
        security.get("anonymousProductionFetch") is True,
        "test-org production fetch must remain anonymous",
        errors,
    )
    require(
        security.get("productionCredentialsUsed") is False,
        "test-org evidence must not use production credentials",
        errors,
    )
    require(
        security.get("workflowPermissions") == "contents-read",
        "test-org workflow permissions must remain contents-read",
        errors,
    )
    require(
        security.get("checkoutCredentialsPersisted") is False,
        "test-org checkout credentials must not persist",
        errors,
    )
    require(
        security.get("immutableActionPins") is True,
        "test-org actions must remain immutable",
        errors,
    )
    require(
        security.get("credentialShapeScan") is True,
        "test-org source credential scan is missing",
        errors,
    )

    process = provenance.get("sharedProcessConsumer", {})
    require(process.get("status") == "success", "process consumer status must be success", errors)
    require(is_sha(process.get("exactHead")), "provenance process head SHA is invalid", errors)
    require(is_sha(process.get("mergeCommit")), "provenance process merge SHA is invalid", errors)
    process_runs = process.get("workflowRuns", [])
    require(
        isinstance(process_runs, list)
        and len(process_runs) == 2
        and all(is_positive_run(run) for run in process_runs),
        "provenance process proof must record two runs",
        errors,
    )
    require_matrix(process, "sharedProcessConsumer", errors)

    records = provenance.get("runtimeConsumers", [])
    require(isinstance(records, list), "runtimeConsumers must be a list", errors)
    by_repository = {
        record.get("productionRepository"): record
        for record in records
        if isinstance(record, dict)
    }
    require(
        set(by_repository) == EXPECTED_CONSUMERS,
        "runtime provenance must contain exactly the four wave consumers",
        errors,
    )

    for repository in sorted(EXPECTED_CONSUMERS):
        record = by_repository.get(repository, {})
        prefix = f"runtimeConsumers[{repository}]"
        require(is_sha(record.get("productionMerge")), f"{prefix} production merge SHA is invalid", errors)
        if repository in EXPECTED_COMPLETE_TEST_ORGS:
            require(
                record.get("status") == "success-interim",
                f"{prefix} must be success-interim",
                errors,
            )
            require(
                record.get("sourceFetch") == "anonymous-exact-sha",
                f"{prefix} source fetch qualification is incorrect",
                errors,
            )
            require(
                record.get("qualification") == "exact-source-runtime-provenance",
                f"{prefix} qualification is incorrect",
                errors,
            )
            require(
                record.get("connectedRepository") is True,
                f"{prefix} connected repository is missing",
                errors,
            )
            require(
                record.get("dedicatedRepository") is False,
                f"{prefix} falsely claims a dedicated repository",
                errors,
            )
            require(is_sha(record.get("exactHead")), f"{prefix} head SHA is invalid", errors)
            require(is_sha(record.get("mergeCommit")), f"{prefix} merge SHA is invalid", errors)
            require(
                is_positive_run(record.get("workflowRun")),
                f"{prefix} workflow run is missing",
                errors,
            )
            require_matrix(record, prefix, errors)
        else:
            require(
                record.get("status") == "blocked-dedicated-repository",
                f"{prefix} blocker status is incorrect",
                errors,
            )
            require(
                record.get("organizationExists") is True,
                f"{prefix} organization existence must be recorded",
                errors,
            )
            require(
                record.get("connectedRepository") is False,
                f"{prefix} falsely claims a connected repository",
                errors,
            )
            require(
                record.get("dedicatedRepository") is False,
                f"{prefix} falsely claims a dedicated repository",
                errors,
            )
            require(
                record.get("followUpLinear") == "DEN-3060",
                f"{prefix} Linear follow-up is incorrect",
                errors,
            )
            require(
                record.get("followUpGitHub") == "ORESoftware/mcp-rust-libs#27",
                f"{prefix} GitHub follow-up is incorrect",
                errors,
            )

    admin = provenance.get("administrativeFollowUp", {})
    require(admin.get("linear") == "DEN-3060", "admin Linear follow-up must be DEN-3060", errors)
    require(
        admin.get("github") == "ORESoftware/mcp-rust-libs#27",
        "admin GitHub follow-up must be issue #27",
        errors,
    )

    closure = provenance.get("publicationClosure", {})
    require(closure.get("linear") == "DEN-3036", "provenance publication blocker is incorrect", errors)
    require(closure.get("readyPackages") == 0, "provenance must not claim published packages", errors)
    require(closure.get("totalPackages") == 23, "provenance closure must contain 23 packages", errors)
    require(
        closure.get("frozenInstallationReady") is False,
        "provenance must not claim frozen-install readiness",
        errors,
    )

    qualification = provenance.get("qualification", {})
    require(
        qualification.get("runtimeAndProvenanceOnly") is True,
        "qualification must be runtime/provenance only",
        errors,
    )
    for key in (
        "zedRegistryPublication",
        "resolverGeneratedZedLock",
        "frozenZedInstall",
        "deploymentEvidence",
        "providerBackedAiConsensus",
    ):
        require(
            qualification.get(key) is False,
            f"qualification must not claim {key}",
            errors,
        )
    return errors


def validate_cross_document(
    wave: dict[str, Any], provenance: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    wave_consumers = {
        consumer["repository"]: consumer
        for consumer in wave.get("consumers", [])
        if isinstance(consumer, dict) and isinstance(consumer.get("repository"), str)
    }
    provenance_consumers = {
        consumer["productionRepository"]: consumer
        for consumer in provenance.get("runtimeConsumers", [])
        if isinstance(consumer, dict)
        and isinstance(consumer.get("productionRepository"), str)
    }

    for repository in sorted(EXPECTED_CONSUMERS):
        wave_record = wave_consumers.get(repository, {})
        provenance_record = provenance_consumers.get(repository, {})
        require(
            wave_record.get("runtime", {}).get("mergeCommit")
            == provenance_record.get("productionMerge"),
            f"{repository} production merge differs between ledgers",
            errors,
        )
        if repository in EXPECTED_COMPLETE_TEST_ORGS:
            wave_test = wave_record.get("testOrganization", {})
            require(
                wave_test.get("exactHead") == provenance_record.get("exactHead"),
                f"{repository} test head differs between ledgers",
                errors,
            )
            require(
                wave_test.get("mergeCommit") == provenance_record.get("mergeCommit"),
                f"{repository} test merge differs between ledgers",
                errors,
            )
            require(
                wave_test.get("workflowRun") == provenance_record.get("workflowRun"),
                f"{repository} test workflow run differs between ledgers",
                errors,
            )

    wave_process = wave.get("sharedProcessConsumerProof", {})
    provenance_process = provenance.get("sharedProcessConsumer", {})
    for key in ("exactHead", "mergeCommit", "workflowRuns", "matrixJobs"):
        require(
            wave_process.get(key) == provenance_process.get(key),
            f"shared process proof {key} differs between ledgers",
            errors,
        )
    return errors


def validate_documents(
    wave: dict[str, Any], provenance: dict[str, Any]
) -> list[str]:
    return (
        validate_wave(wave)
        + validate_provenance(provenance)
        + validate_cross_document(wave, provenance)
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) > 2:
        print(
            "usage: check_wave2_evidence.py [wave-json] [runtime-provenance-json]",
            file=sys.stderr,
        )
        return 2
    wave_path = Path(arguments[0]) if arguments else DEFAULT_WAVE
    provenance_path = Path(arguments[1]) if len(arguments) == 2 else DEFAULT_PROVENANCE
    try:
        wave = load_json(wave_path)
        provenance = load_json(provenance_path)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    errors = validate_documents(wave, provenance)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print(
        "wave-2 evidence valid: four production runtimes, "
        "two complete interim test-org proofs, two explicit provisioning blockers, "
        "and zero of twenty-three Zed packages ready"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
