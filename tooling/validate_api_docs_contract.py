#!/usr/bin/env python3
"""Validate the ORE API-docs discovery and MCP integration contract.

The validator intentionally uses only the Python standard library so Rust,
Node, Dart, Gleam, and mixed-language repositories can run the same gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = "ore.api-docs.v1"
CANONICAL_DISCOVERY_PATH = "/.well-known/api-docs"
CANONICAL_OPENAPI_PATH = "/openapi.json"
OPENAPI_ALIAS = "/api/docs.json"
CANONICAL_UI_PATH = "/api/docs"
UI_ALIAS = "/docs/api"
CANONICAL_INTERNAL_OPENAPI_PATH = "/internal/openapi.json"
CANONICAL_INTERNAL_UI_PATH = "/internal/docs/api"
OPENAPI_MEDIA_TYPE = "application/vnd.oai.openapi+json;version=3.1"

REQUIRED_MCP_TOOLS = (
    "api_docs_discover",
    "api_docs_get_openapi",
    "api_docs_validate",
    "api_docs_list_operations",
    "api_docs_describe_operation",
)
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
SAFE_METHODS = frozenset(("get", "head", "options"))
UNSAFE_METHODS = frozenset(("put", "post", "delete", "patch", "trace"))
VALID_VISIBILITIES = frozenset(("public", "internal"))
VALID_STABILITIES = frozenset(("stable", "beta", "experimental"))
SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MCP_REPOSITORY_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+-mcp-server\.rs)$"
)
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|unknown)$")
OPERATION_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class ContractError(ValueError):
    """A deterministic contract validation failure."""


@dataclass(frozen=True)
class Operation:
    operation_id: str
    path: str
    method: str
    summary: str
    tags: tuple[str, ...]
    visibility: str
    stability: str
    mcp_expose: bool
    mutating: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "operationId": self.operation_id,
            "path": self.path,
            "method": self.method.upper(),
            "summary": self.summary,
            "tags": list(self.tags),
            "visibility": self.visibility,
            "stability": self.stability,
            "mcpExpose": self.mcp_expose,
            "mutating": self.mutating,
        }


@dataclass(frozen=True)
class ValidationSummary:
    service: str
    service_version: str
    openapi_version: str
    openapi_sha256: str
    operation_count: int
    read_only_operation_count: int
    mcp_repository: str
    internal_docs_available: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "service": self.service,
            "serviceVersion": self.service_version,
            "openapiVersion": self.openapi_version,
            "openapiSha256": self.openapi_sha256,
            "operationCount": self.operation_count,
            "readOnlyOperationCount": self.read_only_operation_count,
            "mcpRepository": self.mcp_repository,
            "internalDocsAvailable": self.internal_docs_available,
        }


def _fail(message: str) -> "NoReturn":
    raise ContractError(message)


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _array(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array")
    return value


def _string(value: Any, label: str, *, maximum: int = 2048) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    if not value:
        _fail(f"{label} must not be empty")
    if len(value) > maximum:
        _fail(f"{label} exceeds {maximum} characters")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], label: str, required: Iterable[str], optional: Iterable[str] = ()
) -> None:
    required_set = set(required)
    optional_set = set(optional)
    missing = required_set - set(value)
    if missing:
        _fail(f"{label} is missing required keys: {', '.join(sorted(missing))}")
    unknown = set(value) - required_set - optional_set
    if unknown:
        _fail(f"{label} contains unknown keys: {', '.join(sorted(unknown))}")


def _validate_root_relative_path(value: Any, label: str) -> str:
    path = _string(value, label)
    if not path.startswith("/") or path.startswith("//"):
        _fail(f"{label} must be a root-relative HTTP path")
    if any(character in path for character in ("?", "#", "\\", "\r", "\n", "\t", "\0")):
        _fail(f"{label} must not contain a query, fragment, backslash, or control character")
    if any(ord(character) < 0x20 for character in path):
        _fail(f"{label} must not contain control characters")
    return path


def _validate_aliases(
    value: Any, label: str, *, required_alias: str, forbidden: str
) -> tuple[str, ...]:
    aliases = _array(value, label)
    if not aliases:
        _fail(f"{label} must contain at least one alias")
    parsed = tuple(_validate_root_relative_path(alias, f"{label}[]") for alias in aliases)
    if len(parsed) != len(set(parsed)):
        _fail(f"{label} must not contain duplicate paths")
    if required_alias not in parsed:
        _fail(f"{label} must contain the compatibility alias {required_alias}")
    if forbidden in parsed:
        _fail(f"{label} must not repeat canonical path {forbidden}")
    return parsed


def _owner(repository: str, label: str) -> str:
    if not REPOSITORY_RE.fullmatch(repository):
        _fail(f"{label} must be in owner/repository form")
    return repository.split("/", 1)[0].casefold()


def _validate_manifest(manifest: Any, *, expected_mcp_repository: str | None) -> dict[str, Any]:
    root = _object(manifest, "manifest")
    _require_exact_keys(
        root,
        "manifest",
        required=("schemaVersion", "service", "public", "internal", "mcp", "provenance"),
    )

    if root["schemaVersion"] != SCHEMA_VERSION:
        _fail(f"manifest.schemaVersion must equal {SCHEMA_VERSION}")

    service = _object(root["service"], "manifest.service")
    _require_exact_keys(
        service,
        "manifest.service",
        required=("name", "version"),
        optional=("environment",),
    )
    service_name = _string(service["name"], "manifest.service.name", maximum=128)
    if not SERVICE_NAME_RE.fullmatch(service_name):
        _fail("manifest.service.name must use lowercase DNS-like characters")
    service_version = _string(service["version"], "manifest.service.version", maximum=64)
    if "environment" in service:
        _string(service["environment"], "manifest.service.environment", maximum=64)

    public = _object(root["public"], "manifest.public")
    _require_exact_keys(public, "manifest.public", required=("openapi", "ui"))

    openapi = _object(public["openapi"], "manifest.public.openapi")
    _require_exact_keys(
        openapi,
        "manifest.public.openapi",
        required=("path", "aliases", "mediaType", "sha256"),
    )
    openapi_path = _validate_root_relative_path(
        openapi["path"], "manifest.public.openapi.path"
    )
    if openapi_path != CANONICAL_OPENAPI_PATH:
        _fail(
            f"manifest.public.openapi.path must equal {CANONICAL_OPENAPI_PATH}"
        )
    _validate_aliases(
        openapi["aliases"],
        "manifest.public.openapi.aliases",
        required_alias=OPENAPI_ALIAS,
        forbidden=CANONICAL_OPENAPI_PATH,
    )
    if openapi["mediaType"] != OPENAPI_MEDIA_TYPE:
        _fail(f"manifest.public.openapi.mediaType must equal {OPENAPI_MEDIA_TYPE}")
    declared_sha = _string(
        openapi["sha256"], "manifest.public.openapi.sha256", maximum=64
    )
    if not HEX_64_RE.fullmatch(declared_sha):
        _fail("manifest.public.openapi.sha256 must be 64 lowercase hexadecimal characters")

    ui = _object(public["ui"], "manifest.public.ui")
    _require_exact_keys(ui, "manifest.public.ui", required=("path", "aliases"))
    ui_path = _validate_root_relative_path(ui["path"], "manifest.public.ui.path")
    if ui_path != CANONICAL_UI_PATH:
        _fail(f"manifest.public.ui.path must equal {CANONICAL_UI_PATH}")
    _validate_aliases(
        ui["aliases"],
        "manifest.public.ui.aliases",
        required_alias=UI_ALIAS,
        forbidden=CANONICAL_UI_PATH,
    )

    internal = _object(root["internal"], "manifest.internal")
    _require_exact_keys(internal, "manifest.internal", required=("available",))
    internal_available = _boolean(
        internal["available"], "manifest.internal.available"
    )

    mcp = _object(root["mcp"], "manifest.mcp")
    _require_exact_keys(mcp, "manifest.mcp", required=("repository", "mode", "tools"))
    mcp_repository = _string(
        mcp["repository"], "manifest.mcp.repository", maximum=256
    )
    if not MCP_REPOSITORY_RE.fullmatch(mcp_repository):
        _fail(
            "manifest.mcp.repository must name an owner/*-mcp-server.rs repository"
        )
    if expected_mcp_repository is not None and mcp_repository != expected_mcp_repository:
        _fail(
            "manifest.mcp.repository does not match the repository selected by the validator"
        )
    if mcp["mode"] != "read-only":
        _fail("manifest.mcp.mode must equal read-only")

    tools_raw = _array(mcp["tools"], "manifest.mcp.tools")
    tools = tuple(_string(tool, "manifest.mcp.tools[]", maximum=64) for tool in tools_raw)
    if len(tools) != len(set(tools)):
        _fail("manifest.mcp.tools must not contain duplicates")
    for tool in tools:
        if not TOOL_NAME_RE.fullmatch(tool):
            _fail(f"manifest.mcp.tools contains invalid tool name {tool!r}")
    missing_tools = set(REQUIRED_MCP_TOOLS) - set(tools)
    if missing_tools:
        _fail(
            "manifest.mcp.tools is missing required read-only API-doc tools: "
            + ", ".join(sorted(missing_tools))
        )

    provenance = _object(root["provenance"], "manifest.provenance")
    _require_exact_keys(
        provenance,
        "manifest.provenance",
        required=("sourceRepository", "gitSha"),
    )
    source_repository = _string(
        provenance["sourceRepository"],
        "manifest.provenance.sourceRepository",
        maximum=256,
    )
    source_owner = _owner(
        source_repository, "manifest.provenance.sourceRepository"
    )
    mcp_owner = _owner(mcp_repository, "manifest.mcp.repository")
    if source_owner != mcp_owner:
        _fail(
            "API and MCP repositories must belong to the same GitHub organization"
        )
    git_sha = _string(provenance["gitSha"], "manifest.provenance.gitSha", maximum=64)
    if not GIT_SHA_RE.fullmatch(git_sha):
        _fail(
            "manifest.provenance.gitSha must be a 40/64-character lowercase hash or unknown"
        )

    return {
        "serviceName": service_name,
        "serviceVersion": service_version,
        "declaredSha256": declared_sha,
        "mcpRepository": mcp_repository,
        "internalAvailable": internal_available,
    }


def _validate_operation(
    *,
    path: str,
    method: str,
    operation: Any,
    seen_operation_ids: set[str],
) -> Operation:
    value = _object(operation, f"openapi.paths[{path!r}].{method}")
    operation_id = _string(
        value.get("operationId"),
        f"openapi.paths[{path!r}].{method}.operationId",
        maximum=128,
    )
    if not OPERATION_ID_RE.fullmatch(operation_id):
        _fail(f"operationId {operation_id!r} has invalid characters")
    if operation_id in seen_operation_ids:
        _fail(f"operationId {operation_id!r} is not unique")
    seen_operation_ids.add(operation_id)

    summary = _string(
        value.get("summary"),
        f"openapi operation {operation_id}.summary",
        maximum=300,
    )
    tags_raw = _array(value.get("tags"), f"openapi operation {operation_id}.tags")
    tags = tuple(_string(tag, f"openapi operation {operation_id}.tags[]", maximum=64) for tag in tags_raw)
    if not tags:
        _fail(f"openapi operation {operation_id} must have at least one tag")
    if len(tags) != len(set(tags)):
        _fail(f"openapi operation {operation_id} contains duplicate tags")

    visibility = _string(
        value.get("x-ore-visibility"),
        f"openapi operation {operation_id}.x-ore-visibility",
        maximum=16,
    )
    if visibility not in VALID_VISIBILITIES:
        _fail(
            f"openapi operation {operation_id} has unsupported x-ore-visibility"
        )
    if visibility != "public":
        _fail(
            f"public OpenAPI document contains internal operation {operation_id}"
        )

    stability = _string(
        value.get("x-ore-stability"),
        f"openapi operation {operation_id}.x-ore-stability",
        maximum=16,
    )
    if stability not in VALID_STABILITIES:
        _fail(
            f"openapi operation {operation_id} has unsupported x-ore-stability"
        )
    mcp_expose = _boolean(
        value.get("x-ore-mcp-expose"),
        f"openapi operation {operation_id}.x-ore-mcp-expose",
    )
    mutating = _boolean(
        value.get("x-ore-mcp-mutating"),
        f"openapi operation {operation_id}.x-ore-mcp-mutating",
    )
    if method in SAFE_METHODS and mutating:
        _fail(
            f"safe HTTP operation {operation_id} must not be marked mutating"
        )
    if method in UNSAFE_METHODS and not mutating:
        _fail(
            f"unsafe HTTP operation {operation_id} must be marked mutating"
        )
    if mutating and mcp_expose:
        _fail(
            f"mutating operation {operation_id} cannot be exposed by the baseline read-only MCP"
        )

    responses = _object(
        value.get("responses"), f"openapi operation {operation_id}.responses"
    )
    if not responses:
        _fail(f"openapi operation {operation_id} must define responses")

    return Operation(
        operation_id=operation_id,
        path=path,
        method=method,
        summary=summary,
        tags=tags,
        visibility=visibility,
        stability=stability,
        mcp_expose=mcp_expose,
        mutating=mutating,
    )


def _validate_openapi(openapi: Any) -> tuple[str, list[Operation]]:
    root = _object(openapi, "openapi")
    openapi_version = _string(root.get("openapi"), "openapi.openapi", maximum=32)
    if not openapi_version.startswith("3.1."):
        _fail("public API document must use OpenAPI 3.1.x")

    info = _object(root.get("info"), "openapi.info")
    _string(info.get("title"), "openapi.info.title", maximum=200)
    _string(info.get("version"), "openapi.info.version", maximum=64)

    paths = _object(root.get("paths"), "openapi.paths")
    if not paths:
        _fail("openapi.paths must not be empty")

    seen_operation_ids: set[str] = set()
    operations: list[Operation] = []
    for path in sorted(paths):
        _validate_root_relative_path(path, f"openapi path {path!r}")
        if path.startswith("/internal/"):
            _fail(f"public OpenAPI document must not include internal path {path}")
        path_item = _object(paths[path], f"openapi.paths[{path!r}]")
        for method in HTTP_METHODS:
            if method not in path_item:
                continue
            operations.append(
                _validate_operation(
                    path=path,
                    method=method,
                    operation=path_item[method],
                    seen_operation_ids=seen_operation_ids,
                )
            )

    if not operations:
        _fail("OpenAPI document does not contain any HTTP operations")
    operations.sort(key=lambda operation: operation.operation_id)
    return openapi_version, operations


def validate_contract(
    manifest: Any,
    openapi: Any,
    openapi_bytes: bytes,
    *,
    expected_mcp_repository: str | None = None,
) -> tuple[ValidationSummary, tuple[Operation, ...]]:
    """Validate a manifest and its exact public OpenAPI bytes."""

    if len(openapi_bytes) > 8 * 1024 * 1024:
        _fail("public OpenAPI document exceeds the 8 MiB contract limit")

    manifest_data = _validate_manifest(
        manifest, expected_mcp_repository=expected_mcp_repository
    )
    computed_sha = hashlib.sha256(openapi_bytes).hexdigest()
    if computed_sha != manifest_data["declaredSha256"]:
        _fail(
            "manifest.public.openapi.sha256 does not match the exact OpenAPI response bytes"
        )

    openapi_version, operations = _validate_openapi(openapi)
    summary = ValidationSummary(
        service=manifest_data["serviceName"],
        service_version=manifest_data["serviceVersion"],
        openapi_version=openapi_version,
        openapi_sha256=computed_sha,
        operation_count=len(operations),
        read_only_operation_count=sum(
            1 for operation in operations if operation.mcp_expose and not operation.mutating
        ),
        mcp_repository=manifest_data["mcpRepository"],
        internal_docs_available=manifest_data["internalAvailable"],
    )
    return summary, tuple(operations)


def load_json_file(path: Path, label: str) -> tuple[Any, bytes]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        _fail(f"cannot read {label} at {path}: {error}")
    try:
        return json.loads(payload), payload
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} at {path} is not valid UTF-8 JSON: {error}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate canonical API-doc routes, OpenAPI metadata, and MCP pairing."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--openapi", type=Path, required=True)
    parser.add_argument(
        "--expected-mcp-repository",
        help="Optional exact owner/*-mcp-server.rs repository expected by this lane.",
    )
    parser.add_argument(
        "--operations",
        action="store_true",
        help="Include the normalized operation catalog in JSON output.",
    )
    arguments = parser.parse_args(argv)

    try:
        manifest, _ = load_json_file(arguments.manifest, "manifest")
        openapi, openapi_bytes = load_json_file(arguments.openapi, "OpenAPI document")
        summary, operations = validate_contract(
            manifest,
            openapi,
            openapi_bytes,
            expected_mcp_repository=arguments.expected_mcp_repository,
        )
    except ContractError as error:
        print(f"api-docs contract error: {error}", file=sys.stderr)
        return 1

    result = summary.as_json()
    result["discoveryPath"] = CANONICAL_DISCOVERY_PATH
    result["publicRoutes"] = [
        CANONICAL_OPENAPI_PATH,
        OPENAPI_ALIAS,
        CANONICAL_UI_PATH,
        UI_ALIAS,
    ]
    result["internalRoutes"] = [
        CANONICAL_INTERNAL_OPENAPI_PATH,
        CANONICAL_INTERNAL_UI_PATH,
    ]
    if arguments.operations:
        result["operations"] = [operation.as_json() for operation in operations]
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
