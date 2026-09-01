#!/usr/bin/env python3
"""Validate one exact-revision Rust MCP fleet parity profile.

The JSON Schema owns the portable document shape. This dependency-free
validator enforces the cross-field, repository-source, and evidence invariants
that JSON Schema cannot express. It never executes provider probes and never
reads secret values.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


FINAL_PROTOCOL = "2025-11-25"
EXPECTED_CLIENTS = frozenset(
    {"cursor", "openai", "anthropic", "gemini", "grok", "qwen"}
)
EXPECTED_INTEGRATIONS = frozenset(
    {
        "github",
        "aws",
        "gcp",
        "supabase",
        "neon",
        "cloudflare",
        "k8s_cluster",
        "nats",
    }
)
EXPECTED_STATES = frozenset(
    {"ready", "not_configured", "degraded", "unauthorized", "forbidden"}
)
EXPECTED_TOP_LEVEL = frozenset(
    {
        "schemaVersion",
        "identity",
        "protocol",
        "clients",
        "integrations",
        "organizationSurface",
        "security",
        "evidence",
    }
)
TRUE_REMOTE_AUTH_FIELDS = (
    "protectedResourceMetadata",
    "wwwAuthenticateChallenge",
    "audienceBound",
    "authorizedClientValidated",
    "realmValidated",
    "noTokenPassthrough",
    "exactHostPolicy",
    "credentialedRedirectsDisabled",
    "credentialedAmbientProxyDisabled",
)
TRUE_SECURITY_FIELDS = (
    "secretsEnvironmentOnly",
    "secretValuesExcluded",
    "stdoutProtocolOnly",
    "boundedLowCardinalityTelemetry",
    "exactOriginAllowlists",
    "credentialedRedirectsDisabled",
    "credentialedAmbientProxyDisabled",
)
TRUE_MUTATION_FIELDS = (
    "defaultDenied",
    "runtimeAuthorization",
    "allowlistedTargets",
    "dryRun",
    "targetBoundConfirmation",
    "idempotency",
    "boundedAudit",
)
PROVIDER_ORIGIN_REQUIREMENTS = {
    "github": ("https://api.github.com",),
    "supabase": ("https://",),
    "neon": ("https://console.neon.tech",),
    "cloudflare": ("https://api.cloudflare.com",),
    "aws": ("aws-sdk://", "https://"),
    "gcp": ("gcp-sdk://", "https://"),
    "k8s_cluster": ("kubeconfig://", "https://"),
    "nats": ("nats://", "tls://"),
}
PORTABLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
REPOSITORY = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*-mcp-server\.rs$"
)
REVISION = re.compile(r"^[0-9a-f]{40}$")
LINEAR_ISSUE = re.compile(r"^DEN-[1-9][0-9]*$")
ENVIRONMENT_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
NAMESPACE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
NATS_SUBJECT = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_*>-]+)+$")
IMMUTABLE_URL = re.compile(
    r"^https://[^\s]+/(?:actions/runs/[1-9][0-9]*|commit/[0-9a-f]{40}|releases/tag/[^/?#]+)(?:[/?#].*)?$"
)
SECRET_SHAPES = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"lin_api_[A-Za-z0-9]{20,}"),
    re.compile(r"(?:sk|rk|pk)-(?:live|test|proj)-[A-Za-z0-9_-]{12,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
NO_OP_TERMS = (
    "no-op",
    "noop",
    "placeholder",
    "not implemented",
    "unconditional success",
    "always returns empty",
)


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a mapping while rejecting ambiguous duplicate JSON keys."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object with duplicate-key rejection."""

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("profile root must be a JSON object")
    return value


def mapping(value: Any, location: str, errors: list[str]) -> dict[str, Any]:
    """Return a mapping or record a type error and return an empty mapping."""

    if isinstance(value, dict):
        return value
    errors.append(f"{location}: expected object")
    return {}


def sequence(value: Any, location: str, errors: list[str]) -> list[Any]:
    """Return a list or record a type error and return an empty list."""

    if isinstance(value, list):
        return value
    errors.append(f"{location}: expected array")
    return []


def exact_keys(
    value: dict[str, Any], expected: Iterable[str], location: str, errors: list[str]
) -> None:
    """Require exactly the named object keys."""

    wanted = set(expected)
    actual = set(value)
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing:
        errors.append(f"{location}: missing keys {missing}")
    if extra:
        errors.append(f"{location}: unknown keys {extra}")


def require_true_fields(
    value: dict[str, Any], fields: Iterable[str], location: str, errors: list[str]
) -> None:
    """Require policy booleans to be exactly true."""

    for field in fields:
        if value.get(field) is not True:
            errors.append(f"{location}.{field}: must be true")


def bounded_integer(
    value: Any, minimum: int, maximum: int, location: str, errors: list[str]
) -> None:
    """Validate a non-boolean bounded integer."""

    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{location}: expected integer")
    elif not minimum <= value <= maximum:
        errors.append(f"{location}: must be between {minimum} and {maximum}")


def unique_named_items(
    items: list[Any], field: str, location: str, errors: list[str]
) -> dict[str, dict[str, Any]]:
    """Index object items by a required string field and reject duplicates."""

    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(items):
        item = mapping(raw, f"{location}[{index}]", errors)
        name = item.get(field)
        if not isinstance(name, str) or not name:
            errors.append(f"{location}[{index}].{field}: expected non-empty string")
            continue
        if name in result:
            errors.append(f"{location}: duplicate {field} {name!r}")
        else:
            result[name] = item
    return result


def safe_repository_path(
    root: Path, relative: Any, location: str, errors: list[str]
) -> Path | None:
    """Resolve a repository-owned source path without accepting traversal."""

    if not isinstance(relative, str) or not relative:
        errors.append(f"{location}: expected repository-relative path")
        return None
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        errors.append(f"{location}: path escapes repository root")
        return None
    if not candidate.is_file():
        errors.append(f"{location}: file does not exist: {relative}")
        return None
    return candidate


def validate_timestamp(value: Any, location: str, errors: list[str]) -> None:
    """Require an RFC 3339-compatible timestamp with a timezone."""

    if not isinstance(value, str):
        errors.append(f"{location}: expected date-time string")
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{location}: invalid date-time")
        return
    if parsed.tzinfo is None:
        errors.append(f"{location}: date-time must include a timezone")


def evidence_source_path(reference: str) -> str:
    """Return the source path portion of a local evidence reference."""

    return re.split(r"::|#", reference, maxsplit=1)[0]


def validate_evidence(
    raw: Any,
    location: str,
    root: Path,
    errors: list[str],
    expected_revision: str | None,
) -> None:
    """Validate immutable evidence and local source-test references."""

    item = mapping(raw, location, errors)
    exact_keys(item, ("kind", "reference", "revision", "verifiedAt"), location, errors)
    kind = item.get("kind")
    if kind not in {
        "source_test",
        "github_run",
        "test_org_run",
        "client_smoke",
        "live_read_probe",
    }:
        errors.append(f"{location}.kind: unsupported evidence kind")
    revision = item.get("revision")
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        errors.append(f"{location}.revision: expected 40 lowercase hex characters")
    elif expected_revision is not None and revision != expected_revision:
        errors.append(f"{location}.revision: must equal profile revision")
    reference = item.get("reference")
    if not isinstance(reference, str) or not reference:
        errors.append(f"{location}.reference: expected non-empty string")
    elif kind == "source_test":
        safe_repository_path(
            root,
            evidence_source_path(reference),
            f"{location}.reference",
            errors,
        )
    elif reference.startswith("https://"):
        if IMMUTABLE_URL.fullmatch(reference) is None:
            errors.append(
                f"{location}.reference: URL must identify an immutable commit, release, or Actions run"
            )
    else:
        safe_repository_path(
            root,
            evidence_source_path(reference),
            f"{location}.reference",
            errors,
        )
    validate_timestamp(item.get("verifiedAt"), f"{location}.verifiedAt", errors)


def validate_implementation(
    raw: Any, location: str, root: Path, errors: list[str]
) -> tuple[Path | None, Path | None, str | None]:
    """Require an implementation module, symbol, and focused test."""

    item = mapping(raw, location, errors)
    exact_keys(item, ("module", "symbol", "test"), location, errors)
    module = safe_repository_path(root, item.get("module"), f"{location}.module", errors)
    test = safe_repository_path(root, item.get("test"), f"{location}.test", errors)
    symbol = item.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        errors.append(f"{location}.symbol: expected non-empty string")
        return module, test, None
    needle = symbol.rsplit("::", maxsplit=1)[-1].split("<", maxsplit=1)[0]
    if module is not None and needle not in module.read_text(encoding="utf-8"):
        errors.append(f"{location}.symbol: {needle!r} not found in {item.get('module')}")
    return module, test, symbol


def validate_identity(profile: dict[str, Any], errors: list[str]) -> tuple[str, str]:
    """Validate repository identity and return revision plus organization."""

    identity = mapping(profile.get("identity"), "identity", errors)
    exact_keys(
        identity,
        ("organization", "repository", "revision", "linearIssue", "serverName", "summary"),
        "identity",
        errors,
    )
    organization = identity.get("organization")
    if not isinstance(organization, str) or PORTABLE_NAME.fullmatch(organization) is None:
        errors.append("identity.organization: invalid portable organization name")
        organization = ""
    repository = identity.get("repository")
    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        errors.append("identity.repository: expected org/*-mcp-server.rs")
    elif organization and repository.split("/", maxsplit=1)[0].casefold() != organization.casefold():
        errors.append("identity.repository: owner must match identity.organization")
    revision = identity.get("revision")
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        errors.append("identity.revision: expected 40 lowercase hex characters")
        revision = ""
    linear_issue = identity.get("linearIssue")
    if not isinstance(linear_issue, str) or LINEAR_ISSUE.fullmatch(linear_issue) is None:
        errors.append("identity.linearIssue: expected DEN-<number>")
    server_name = identity.get("serverName")
    if not isinstance(server_name, str) or PORTABLE_NAME.fullmatch(server_name) is None:
        errors.append("identity.serverName: invalid portable server name")
    summary = identity.get("summary")
    if not isinstance(summary, str) or not 40 <= len(summary) <= 500:
        errors.append("identity.summary: must contain 40..500 characters")
    return revision, organization


def validate_protocol(
    profile: dict[str, Any], revision: str, root: Path, errors: list[str]
) -> None:
    """Validate final protocol, local/remote transport, and OAuth boundaries."""

    protocol = mapping(profile.get("protocol"), "protocol", errors)
    exact_keys(protocol, ("finalRevision", "transports", "remoteAuthorization"), "protocol", errors)
    if protocol.get("finalRevision") != FINAL_PROTOCOL:
        errors.append(f"protocol.finalRevision: must equal {FINAL_PROTOCOL}")
    transports = sequence(protocol.get("transports"), "protocol.transports", errors)
    by_kind = unique_named_items(transports, "kind", "protocol.transports", errors)
    for required in ("stdio", "streamable_http"):
        if required not in by_kind:
            errors.append(f"protocol.transports: missing required {required!r} transport")
    for kind, transport in by_kind.items():
        allowed_keys = {"kind", "enabled", "authentication", "evidence"}
        if kind != "stdio":
            allowed_keys.add("endpointPath")
        exact_keys(transport, allowed_keys, f"protocol.transports[{kind}]", errors)
        if kind not in {"stdio", "streamable_http", "legacy_sse"}:
            errors.append(f"protocol.transports[{kind}]: unsupported transport")
        if transport.get("enabled") is not True:
            errors.append(f"protocol.transports[{kind}].enabled: must be true")
        expected_auth = "process_boundary" if kind == "stdio" else "oauth_2_1"
        if transport.get("authentication") != expected_auth:
            errors.append(
                f"protocol.transports[{kind}].authentication: must equal {expected_auth}"
            )
        if kind != "stdio" and transport.get("endpointPath") != "/mcp":
            errors.append(f"protocol.transports[{kind}].endpointPath: must equal /mcp")
        for index, item in enumerate(
            sequence(transport.get("evidence"), f"protocol.transports[{kind}].evidence", errors)
        ):
            validate_evidence(
                item,
                f"protocol.transports[{kind}].evidence[{index}]",
                root,
                errors,
                revision,
            )
    remote = mapping(protocol.get("remoteAuthorization"), "protocol.remoteAuthorization", errors)
    exact_keys(
        remote,
        (
            "authority",
            *TRUE_REMOTE_AUTH_FIELDS,
            "requestBodyMaxBytes",
            "responseBodyMaxBytes",
        ),
        "protocol.remoteAuthorization",
        errors,
    )
    if remote.get("authority") != "shared-auth":
        errors.append("protocol.remoteAuthorization.authority: must equal shared-auth")
    require_true_fields(remote, TRUE_REMOTE_AUTH_FIELDS, "protocol.remoteAuthorization", errors)
    bounded_integer(
        remote.get("requestBodyMaxBytes"),
        1024,
        1_048_576,
        "protocol.remoteAuthorization.requestBodyMaxBytes",
        errors,
    )
    bounded_integer(
        remote.get("responseBodyMaxBytes"),
        1024,
        1_048_576,
        "protocol.remoteAuthorization.responseBodyMaxBytes",
        errors,
    )


def validate_clients(
    profile: dict[str, Any], revision: str, root: Path, errors: list[str]
) -> None:
    """Require exactly one evidence-backed entry for every supported client."""

    clients = sequence(profile.get("clients"), "clients", errors)
    by_id = unique_named_items(clients, "id", "clients", errors)
    actual = set(by_id)
    if actual != EXPECTED_CLIENTS:
        errors.append(
            f"clients: expected exactly {sorted(EXPECTED_CLIENTS)}, got {sorted(actual)}"
        )
    for client_id, item in by_id.items():
        exact_keys(item, ("id", "role", "transports", "evidence"), f"clients[{client_id}]", errors)
        if item.get("role") != "mcp_client":
            errors.append(f"clients[{client_id}].role: must equal mcp_client")
        transports = sequence(item.get("transports"), f"clients[{client_id}].transports", errors)
        if not transports or len(transports) != len(set(transports)):
            errors.append(f"clients[{client_id}].transports: must be non-empty and unique")
        if any(value not in {"stdio", "streamable_http"} for value in transports):
            errors.append(f"clients[{client_id}].transports: unsupported transport")
        evidence = sequence(item.get("evidence"), f"clients[{client_id}].evidence", errors)
        if not evidence:
            errors.append(f"clients[{client_id}].evidence: at least one entry is required")
        for index, entry in enumerate(evidence):
            validate_evidence(
                entry,
                f"clients[{client_id}].evidence[{index}]",
                root,
                errors,
                revision,
            )


def validate_origin(origin: Any, provider: str, location: str, errors: list[str]) -> None:
    """Reject credentials, fragments, wildcards, and unsupported endpoint classes."""

    if not isinstance(origin, str) or not origin:
        errors.append(f"{location}: expected non-empty origin or endpoint class")
        return
    if "*" in origin or "{" in origin or "}" in origin:
        errors.append(f"{location}: wildcard or template origins are forbidden")
    parsed = urlsplit(origin)
    if parsed.username is not None or parsed.password is not None:
        errors.append(f"{location}: credentials in origins are forbidden")
    if parsed.query or parsed.fragment:
        errors.append(f"{location}: query and fragment components are forbidden")
    prefixes = PROVIDER_ORIGIN_REQUIREMENTS.get(provider, ())
    if not any(origin.startswith(prefix) for prefix in prefixes):
        errors.append(f"{location}: unsupported endpoint class for {provider}")
    if origin.startswith("https://") and parsed.path not in {"", "/"}:
        errors.append(f"{location}: HTTPS allowlist entries must be origins, not paths")


def validate_integrations(
    profile: dict[str, Any], revision: str, root: Path, errors: list[str]
) -> dict[str, dict[str, Any]]:
    """Validate all provider adapters and their real read operations."""

    integrations = sequence(profile.get("integrations"), "integrations", errors)
    by_id = unique_named_items(integrations, "id", "integrations", errors)
    actual = set(by_id)
    if actual != EXPECTED_INTEGRATIONS:
        errors.append(
            f"integrations: expected exactly {sorted(EXPECTED_INTEGRATIONS)}, got {sorted(actual)}"
        )
    for provider, item in by_id.items():
        exact_keys(
            item,
            (
                "id",
                "role",
                "implementation",
                "configurationKeys",
                "allowedOrigins",
                "scopes",
                "stateModel",
                "operations",
                "evidence",
            ),
            f"integrations[{provider}]",
            errors,
        )
        if item.get("role") != "upstream_service":
            errors.append(f"integrations[{provider}].role: must equal upstream_service")
        module, test, _ = validate_implementation(
            item.get("implementation"), f"integrations[{provider}].implementation", root, errors
        )
        keys = sequence(item.get("configurationKeys"), f"integrations[{provider}].configurationKeys", errors)
        if not keys or len(keys) != len(set(keys)):
            errors.append(
                f"integrations[{provider}].configurationKeys: must be non-empty and unique"
            )
        for index, key in enumerate(keys):
            if not isinstance(key, str) or ENVIRONMENT_KEY.fullmatch(key) is None:
                errors.append(
                    f"integrations[{provider}].configurationKeys[{index}]: invalid environment key name"
                )
        origins = sequence(item.get("allowedOrigins"), f"integrations[{provider}].allowedOrigins", errors)
        if not origins or len(origins) != len(set(origins)):
            errors.append(f"integrations[{provider}].allowedOrigins: must be non-empty and unique")
        for index, origin in enumerate(origins):
            validate_origin(
                origin,
                provider,
                f"integrations[{provider}].allowedOrigins[{index}]",
                errors,
            )
        scopes = sequence(item.get("scopes"), f"integrations[{provider}].scopes", errors)
        if not scopes or len(scopes) != len(set(scopes)):
            errors.append(f"integrations[{provider}].scopes: must be non-empty and unique")
        states = sequence(item.get("stateModel"), f"integrations[{provider}].stateModel", errors)
        if set(states) != EXPECTED_STATES or len(states) != len(EXPECTED_STATES):
            errors.append(
                f"integrations[{provider}].stateModel: expected exactly {sorted(EXPECTED_STATES)}"
            )
        operations = sequence(item.get("operations"), f"integrations[{provider}].operations", errors)
        operations_by_name = unique_named_items(
            operations, "name", f"integrations[{provider}].operations", errors
        )
        if len(operations_by_name) < 2:
            errors.append(f"integrations[{provider}].operations: at least two are required")
        if not any(operation.get("mode") == "read" for operation in operations_by_name.values()):
            errors.append(f"integrations[{provider}].operations: at least one real read is required")
        combined_source = ""
        if module is not None:
            combined_source += module.read_text(encoding="utf-8")
        if test is not None:
            combined_source += "\n" + test.read_text(encoding="utf-8")
        for operation_name, operation in operations_by_name.items():
            exact_keys(
                operation,
                (
                    "name",
                    "mode",
                    "description",
                    "organizationScope",
                    "timeoutMs",
                    "outputMaxBytes",
                ),
                f"integrations[{provider}].operations[{operation_name}]",
                errors,
            )
            if operation.get("mode") not in {"diagnostic", "read", "mutation"}:
                errors.append(
                    f"integrations[{provider}].operations[{operation_name}].mode: invalid mode"
                )
            description = operation.get("description")
            if not isinstance(description, str) or not 30 <= len(description) <= 500:
                errors.append(
                    f"integrations[{provider}].operations[{operation_name}].description: must contain 30..500 characters"
                )
            scope = operation.get("organizationScope")
            if not isinstance(scope, str) or len(scope) < 2 or scope in {"*", "all", "any"}:
                errors.append(
                    f"integrations[{provider}].operations[{operation_name}].organizationScope: must be explicit"
                )
            bounded_integer(
                operation.get("timeoutMs"),
                100,
                60_000,
                f"integrations[{provider}].operations[{operation_name}].timeoutMs",
                errors,
            )
            bounded_integer(
                operation.get("outputMaxBytes"),
                256,
                1_048_576,
                f"integrations[{provider}].operations[{operation_name}].outputMaxBytes",
                errors,
            )
            if operation_name not in combined_source:
                errors.append(
                    f"integrations[{provider}].operations[{operation_name}]: name is absent from implementation and focused test"
                )
        evidence = sequence(item.get("evidence"), f"integrations[{provider}].evidence", errors)
        if not evidence:
            errors.append(f"integrations[{provider}].evidence: at least one entry is required")
        for index, entry in enumerate(evidence):
            validate_evidence(
                entry,
                f"integrations[{provider}].evidence[{index}]",
                root,
                errors,
                revision,
            )
    return by_id


def validate_tool(
    name: str,
    item: dict[str, Any],
    integrations: set[str],
    root: Path,
    errors: list[str],
) -> None:
    """Validate one organization-specific, bounded, annotated tool."""

    exact_keys(
        item,
        (
            "name",
            "description",
            "implementation",
            "integrations",
            "annotations",
            "inputSchemaClosed",
            "outputMaxBytes",
        ),
        f"organizationSurface.tools[{name}]",
        errors,
    )
    description = item.get("description")
    if not isinstance(description, str) or not 40 <= len(description) <= 700:
        errors.append(
            f"organizationSurface.tools[{name}].description: must contain 40..700 characters"
        )
    else:
        normalized = f"{name} {description}".casefold()
        for term in NO_OP_TERMS:
            if term in normalized:
                errors.append(
                    f"organizationSurface.tools[{name}]: no-op marker {term!r} is forbidden"
                )
    validate_implementation(
        item.get("implementation"),
        f"organizationSurface.tools[{name}].implementation",
        root,
        errors,
    )
    providers = sequence(
        item.get("integrations"), f"organizationSurface.tools[{name}].integrations", errors
    )
    if not providers or len(providers) != len(set(providers)):
        errors.append(
            f"organizationSurface.tools[{name}].integrations: must be non-empty and unique"
        )
    unknown = set(providers) - integrations
    if unknown:
        errors.append(
            f"organizationSurface.tools[{name}].integrations: unknown providers {sorted(unknown)}"
        )
    annotations = mapping(
        item.get("annotations"), f"organizationSurface.tools[{name}].annotations", errors
    )
    exact_keys(
        annotations,
        ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"),
        f"organizationSurface.tools[{name}].annotations",
        errors,
    )
    if any(not isinstance(annotations.get(field), bool) for field in annotations):
        errors.append(f"organizationSurface.tools[{name}].annotations: all hints must be booleans")
    if annotations.get("readOnlyHint") is True and annotations.get("destructiveHint") is not False:
        errors.append(
            f"organizationSurface.tools[{name}].annotations: read-only tools cannot be destructive"
        )
    if item.get("inputSchemaClosed") is not True:
        errors.append(f"organizationSurface.tools[{name}].inputSchemaClosed: must be true")
    bounded_integer(
        item.get("outputMaxBytes"),
        256,
        1_048_576,
        f"organizationSurface.tools[{name}].outputMaxBytes",
        errors,
    )


def validate_organization_surface(
    profile: dict[str, Any],
    organization: str,
    integrations: dict[str, dict[str, Any]],
    root: Path,
    errors: list[str],
) -> None:
    """Require a concrete organization map and useful MCP surface."""

    surface = mapping(profile.get("organizationSurface"), "organizationSurface", errors)
    exact_keys(
        surface,
        (
            "repositories",
            "services",
            "kubernetesNamespaces",
            "natsSubjects",
            "runbooks",
            "tools",
            "resources",
            "prompts",
            "composedReadTool",
        ),
        "organizationSurface",
        errors,
    )
    repositories = sequence(surface.get("repositories"), "organizationSurface.repositories", errors)
    if not repositories or len(repositories) != len(set(repositories)):
        errors.append("organizationSurface.repositories: must be non-empty and unique")
    identity_repository = mapping(profile.get("identity"), "identity", errors).get("repository")
    if identity_repository not in repositories:
        errors.append("organizationSurface.repositories: must include identity.repository")
    for repository in repositories:
        if not isinstance(repository, str) or "/" not in repository:
            errors.append("organizationSurface.repositories: invalid org/repo entry")
        elif organization and repository.split("/", maxsplit=1)[0].casefold() != organization.casefold():
            errors.append(
                f"organizationSurface.repositories: {repository!r} is outside the owning organization"
            )
    for field in ("services", "runbooks"):
        values = sequence(surface.get(field), f"organizationSurface.{field}", errors)
        if not values or len(values) != len(set(values)):
            errors.append(f"organizationSurface.{field}: must be non-empty and unique")
    namespaces = sequence(
        surface.get("kubernetesNamespaces"), "organizationSurface.kubernetesNamespaces", errors
    )
    if not namespaces or len(namespaces) != len(set(namespaces)):
        errors.append("organizationSurface.kubernetesNamespaces: must be non-empty and unique")
    for namespace in namespaces:
        if not isinstance(namespace, str) or len(namespace) > 63 or NAMESPACE.fullmatch(namespace) is None:
            errors.append(
                f"organizationSurface.kubernetesNamespaces: invalid namespace {namespace!r}"
            )
    subjects = sequence(surface.get("natsSubjects"), "organizationSurface.natsSubjects", errors)
    if not subjects or len(subjects) != len(set(subjects)):
        errors.append("organizationSurface.natsSubjects: must be non-empty and unique")
    for subject in subjects:
        if not isinstance(subject, str) or NATS_SUBJECT.fullmatch(subject) is None or subject in {">", "*"}:
            errors.append(f"organizationSurface.natsSubjects: invalid subject {subject!r}")
    tools = sequence(surface.get("tools"), "organizationSurface.tools", errors)
    tools_by_name = unique_named_items(tools, "name", "organizationSurface.tools", errors)
    if len(tools_by_name) < 8:
        errors.append("organizationSurface.tools: at least eight unique tools are required")
    integration_ids = set(integrations)
    for name, item in tools_by_name.items():
        validate_tool(name, item, integration_ids, root, errors)
    composed = surface.get("composedReadTool")
    if composed not in tools_by_name:
        errors.append("organizationSurface.composedReadTool: must name a declared tool")
    else:
        item = tools_by_name[composed]
        providers = item.get("integrations")
        if not isinstance(providers, list) or len(set(providers)) < 2:
            errors.append(
                "organizationSurface.composedReadTool: must compose at least two integrations"
            )
        annotations = item.get("annotations")
        if not isinstance(annotations, dict) or annotations.get("readOnlyHint") is not True:
            errors.append("organizationSurface.composedReadTool: must be read-only")
    resources = sequence(surface.get("resources"), "organizationSurface.resources", errors)
    resources_by_uri = unique_named_items(resources, "uri", "organizationSurface.resources", errors)
    if len(resources_by_uri) < 3:
        errors.append("organizationSurface.resources: at least three unique resources are required")
    for uri, item in resources_by_uri.items():
        exact_keys(item, ("uri", "description", "mimeType"), f"organizationSurface.resources[{uri}]", errors)
        parsed = urlsplit(uri)
        if not parsed.scheme or not parsed.netloc:
            errors.append(f"organizationSurface.resources[{uri}].uri: expected absolute URI")
        description = item.get("description")
        if not isinstance(description, str) or not 30 <= len(description) <= 500:
            errors.append(
                f"organizationSurface.resources[{uri}].description: must contain 30..500 characters"
            )
        if item.get("mimeType") not in {"application/json", "text/markdown", "text/plain"}:
            errors.append(f"organizationSurface.resources[{uri}].mimeType: unsupported MIME type")
    prompts = sequence(surface.get("prompts"), "organizationSurface.prompts", errors)
    prompts_by_name = unique_named_items(prompts, "name", "organizationSurface.prompts", errors)
    if len(prompts_by_name) < 2:
        errors.append("organizationSurface.prompts: at least two unique prompts are required")
    for name, item in prompts_by_name.items():
        exact_keys(
            item,
            ("name", "description", "referencedTools"),
            f"organizationSurface.prompts[{name}]",
            errors,
        )
        description = item.get("description")
        if not isinstance(description, str) or not 30 <= len(description) <= 500:
            errors.append(
                f"organizationSurface.prompts[{name}].description: must contain 30..500 characters"
            )
        references = sequence(
            item.get("referencedTools"),
            f"organizationSurface.prompts[{name}].referencedTools",
            errors,
        )
        if not references or len(references) != len(set(references)):
            errors.append(
                f"organizationSurface.prompts[{name}].referencedTools: must be non-empty and unique"
            )
        unknown = set(references) - set(tools_by_name)
        if unknown:
            errors.append(
                f"organizationSurface.prompts[{name}].referencedTools: unknown tools {sorted(unknown)}"
            )


def validate_security(profile: dict[str, Any], errors: list[str]) -> None:
    """Require the complete fail-closed fleet policy."""

    security = mapping(profile.get("security"), "security", errors)
    exact_keys(security, (*TRUE_SECURITY_FIELDS, "mutationGate"), "security", errors)
    require_true_fields(security, TRUE_SECURITY_FIELDS, "security", errors)
    gate = mapping(security.get("mutationGate"), "security.mutationGate", errors)
    exact_keys(gate, TRUE_MUTATION_FIELDS, "security.mutationGate", errors)
    require_true_fields(gate, TRUE_MUTATION_FIELDS, "security.mutationGate", errors)


def validate_fleet_evidence(
    profile: dict[str, Any], revision: str, root: Path, errors: list[str]
) -> None:
    """Validate repository, test-organization, lockfile, and shared-pin evidence."""

    evidence = mapping(profile.get("evidence"), "evidence", errors)
    exact_keys(
        evidence,
        ("repositoryTests", "testOrganization", "sharedLibraryRevision", "lockfileCommitted"),
        "evidence",
        errors,
    )
    repository_tests = sequence(evidence.get("repositoryTests"), "evidence.repositoryTests", errors)
    if not repository_tests:
        errors.append("evidence.repositoryTests: at least one entry is required")
    for index, entry in enumerate(repository_tests):
        validate_evidence(
            entry,
            f"evidence.repositoryTests[{index}]",
            root,
            errors,
            revision,
        )
    test_org = mapping(evidence.get("testOrganization"), "evidence.testOrganization", errors)
    exact_keys(
        test_org,
        ("repository", "productionRevision", "evidence"),
        "evidence.testOrganization",
        errors,
    )
    repository = test_org.get("repository")
    if not isinstance(repository, str) or "-test/" not in repository:
        errors.append("evidence.testOrganization.repository: expected a sibling test-org repository")
    if test_org.get("productionRevision") != revision:
        errors.append("evidence.testOrganization.productionRevision: must equal profile revision")
    validate_evidence(
        test_org.get("evidence"),
        "evidence.testOrganization.evidence",
        root,
        errors,
        None,
    )
    shared_revision = evidence.get("sharedLibraryRevision")
    if not isinstance(shared_revision, str) or REVISION.fullmatch(shared_revision) is None:
        errors.append("evidence.sharedLibraryRevision: expected 40 lowercase hex characters")
    if evidence.get("lockfileCommitted") is not True:
        errors.append("evidence.lockfileCommitted: must be true")
    lockfile = root / "Cargo.lock"
    if not lockfile.is_file() or lockfile.stat().st_size == 0:
        errors.append("evidence.lockfileCommitted: repository Cargo.lock is missing or empty")


def validate_secret_absence(profile: dict[str, Any], errors: list[str]) -> None:
    """Reject credential-shaped strings while permitting secret key names."""

    serialized = json.dumps(profile, sort_keys=True)
    for pattern in SECRET_SHAPES:
        if pattern.search(serialized):
            errors.append("profile: credential-shaped value is forbidden")
            return


def validate_profile(profile: dict[str, Any], root: Path) -> list[str]:
    """Return every deterministic validation error for one profile."""

    errors: list[str] = []
    exact_keys(profile, EXPECTED_TOP_LEVEL, "profile", errors)
    if profile.get("schemaVersion") != 1:
        errors.append("schemaVersion: must equal 1")
    revision, organization = validate_identity(profile, errors)
    validate_protocol(profile, revision, root, errors)
    validate_clients(profile, revision, root, errors)
    integrations = validate_integrations(profile, revision, root, errors)
    validate_organization_surface(profile, organization, integrations, root, errors)
    validate_security(profile, errors)
    validate_fleet_evidence(profile, revision, root, errors)
    validate_secret_absence(profile, errors)
    return sorted(set(errors))


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse the narrow validator CLI."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--json", action="store_true", help="emit a machine-readable result")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Validate a profile and report all failures without secret values."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        profile = load_json(args.profile)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        result = {"ok": False, "errors": [f"profile: {error}"]}
    else:
        errors = validate_profile(profile, args.repo_root)
        result = {"ok": not errors, "errors": errors}
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    elif result["ok"]:
        print("MCP fleet parity profile: PASS")
    else:
        print("MCP fleet parity profile: FAIL", file=sys.stderr)
        for error in result["errors"]:
            print(f"- {error}", file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
