#!/usr/bin/env python3
"""Static, fail-closed audit for one Rust MCP server repository.

The scanner intentionally reports review signals rather than pretending static
text search proves security. High findings represent patterns that are unsafe by
default for deployable MCP servers; medium findings require an explicit design
review or a repository-local exception with evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
import tomllib
from pathlib import Path

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
STALE_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
MUTATION_WORDS = re.compile(
    r"\b(?:create|update|delete|remove|assign|dispatch|execute|apply|start|stop|abort|arm|disarm|rotate|revoke|issue|publish|trigger|send|write|upload)_[a-z0-9_]+\b",
    re.IGNORECASE,
)
MUTATION_GATES = (
    "allow_mutation",
    "allow_mutations",
    "mutations_enabled",
    "read_only",
    "confirmation",
    "idempotency",
    "dry_run",
    "require_approval",
)


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    path: str | None = None


def dependency_version(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("version"), str):
        return value["version"]
    return None


def rust_sources(root: Path) -> list[Path]:
    return sorted((root / "src").rglob("*.rs")) if (root / "src").is_dir() else []


def production_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").split("#[cfg(test)]", 1)[0]


def workflow_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    if not workflows:
        return [Finding("medium", "missing-ci", "no GitHub Actions workflow detected")]
    mutable_action = re.compile(r"^\s*(?:-\s+)?uses:\s+[^\s#]+@(?:main|master|v\d+(?:\.\d+)*)\s*$", re.MULTILINE)
    checkout = re.compile(r"uses:\s+actions/checkout@", re.IGNORECASE)
    for path in workflows:
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(root).as_posix()
        if mutable_action.search(text):
            findings.append(
                Finding(
                    "high",
                    "mutable-action-pin",
                    "workflow uses a mutable branch or version tag instead of an immutable action revision",
                    relative,
                )
            )
        if not re.search(r"^permissions:\s*$", text, re.MULTILINE):
            findings.append(
                Finding(
                    "medium",
                    "workflow-permissions",
                    "workflow has no explicit top-level permissions boundary",
                    relative,
                )
            )
        if checkout.search(text) and "persist-credentials: false" not in text:
            findings.append(
                Finding(
                    "low",
                    "checkout-credentials",
                    "checkout credentials are not explicitly discarded",
                    relative,
                )
            )
    return findings


def audit(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    cargo = root / "Cargo.toml"
    manifest = tomllib.loads(cargo.read_text(encoding="utf-8")) if cargo.is_file() else {}
    dependencies = manifest.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}
    sources = rust_sources(root)
    combined = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in sources)
    production = "\n".join(production_text(path) for path in sources)
    if not sources:
        return [Finding("high", "missing-source", "src contains no Rust source files")]

    rmcp = dependency_version(dependencies.get("rmcp"))
    if rmcp is None:
        code = "handwritten-jsonrpc" if "jsonrpc" in combined.lower() else "missing-rmcp"
        severity = "high" if code == "handwritten-jsonrpc" else "medium"
        findings.append(Finding(severity, code, "official rmcp transport is not detected"))
    else:
        major = re.search(r"(?:^|[^0-9])(\d+)", rmcp)
        if major and int(major.group(1)) < 3:
            findings.append(
                Finding(
                    "medium",
                    "rmcp-major",
                    f"rmcp {rmcp!r} requires a reviewed 3.x migration",
                )
            )

    for version in STALE_PROTOCOLS:
        if version in production:
            findings.append(
                Finding(
                    "high" if version == "2024-11-05" else "medium",
                    "stale-protocol",
                    f"production source hard-codes MCP {version}",
                )
            )

    patterns = (
        (
            r"\.wait_with_output\s*\(",
            "high",
            "unbounded-subprocess-output",
            "wait_with_output buffers complete child output",
        ),
        (
            r"\.output\s*\(\s*\)",
            "medium",
            "unbounded-subprocess-output",
            "Command::output may buffer unbounded child output",
        ),
        (
            r"\.(?:bytes|text)\s*\(\s*\)\s*\.await",
            "medium",
            "unbounded-http-body",
            "response body is buffered before an obvious byte ceiling",
        ),
        (
            r"\.json(?:\s*::[^\(]+)?\s*\(\s*\)\s*\.await",
            "medium",
            "unbounded-http-body",
            "response JSON is buffered before an obvious byte ceiling",
        ),
        (
            r"\b(?:print|println)!\s*\(",
            "high",
            "stdout-pollution",
            "stdout writes can corrupt MCP stdio",
        ),
    )
    for path in sources:
        text = production_text(path)
        for pattern, severity, code, message in patterns:
            if re.search(pattern, text):
                findings.append(Finding(severity, code, message, path.relative_to(root).as_posix()))

    bearer = any(
        token in production
        for token in (".bearer_auth(", "AUTHORIZATION", "Authorization", "Bearer ")
    )
    redirect_denied = any(
        token in production
        for token in ("Policy::none", "redirect::Policy::none", "RedirectPolicy::None")
    )
    proxy_disabled = any(token in production for token in (".no_proxy()", "Proxy::custom"))
    exact_host_policy = any(
        token in production.lower()
        for token in ("allowed_hosts", "allowlisted_hosts", "host_allowlist", "exact host")
    )
    if bearer and not redirect_denied:
        findings.append(
            Finding(
                "high",
                "bearer-redirect-policy",
                "bearer client lacks an obvious redirect-denial policy",
            )
        )
    if bearer and not proxy_disabled:
        findings.append(
            Finding(
                "high",
                "bearer-proxy-policy",
                "bearer client can inherit ambient HTTP proxy settings",
            )
        )
    if bearer and ("Url::parse" in production or "base_url" in production) and not exact_host_policy:
        findings.append(
            Finding(
                "medium",
                "bearer-host-policy",
                "configurable bearer origin has no obvious exact host allowlist",
            )
        )

    streamable_http = any(
        token in combined
        for token in ("transport-streamable-http", "StreamableHttpService", "streamable_http")
    )
    if streamable_http and not bearer:
        findings.append(
            Finding(
                "high",
                "http-auth-boundary",
                "Streamable HTTP transport has no obvious bearer authorization boundary",
            )
        )
    if streamable_http and not any(token in combined for token in ("allowed_hosts", "with_allowed_hosts")):
        findings.append(
            Finding(
                "medium",
                "http-host-boundary",
                "Streamable HTTP transport has no obvious Host allowlist",
            )
        )

    tool_inputs = "Parameters<" in combined or "#[tool" in combined
    if tool_inputs and "deny_unknown_fields" not in combined:
        findings.append(
            Finding(
                "medium",
                "permissive-tool-schema",
                "tool input structs do not visibly reject unknown fields",
            )
        )

    mutation_names = sorted(set(match.group(0) for match in MUTATION_WORDS.finditer(production)))
    if mutation_names and not any(gate in production.lower() for gate in MUTATION_GATES):
        findings.append(
            Finding(
                "high",
                "mutation-gate",
                "mutating tool names are present without an obvious runtime gate, confirmation, idempotency, or dry-run boundary: "
                + ", ".join(mutation_names[:8]),
            )
        )
    elif mutation_names and "confirmation" not in production.lower():
        findings.append(
            Finding(
                "medium",
                "mutation-confirmation",
                "mutating tools lack an obvious per-operation confirmation boundary",
            )
        )

    renders_json = any(
        token in production
        for token in ("to_string_pretty", "to_string(", "ContentBlock::text", "CallToolResult::success")
    )
    output_bounded = any(
        token in production.lower()
        for token in ("max_tool_output", "output_limit", "bounded_output", "truncate_utf8", "max_output_bytes")
    )
    if renders_json and not output_bounded:
        findings.append(
            Finding(
                "medium",
                "unbounded-tool-output",
                "serialized or text MCP results have no obvious final output ceiling",
            )
        )

    if not (root / "Cargo.lock").is_file():
        findings.append(Finding("low", "missing-lock", "Cargo.lock is absent for a deployable server"))
    findings.extend(workflow_findings(root))
    if "#[cfg(test)]" not in combined and not (root / "tests").is_dir():
        findings.append(Finding("medium", "missing-tests", "no Rust tests detected"))
    process_test = False
    if (root / "tests").is_dir():
        integration = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted((root / "tests").rglob("*.rs"))
        )
        process_test = "CARGO_BIN_EXE_" in integration and "initialize" in integration
    if not process_test:
        findings.append(
            Finding(
                "medium",
                "missing-process-conformance",
                "no real-binary initialize/tools lifecycle test was detected",
            )
        )
    return sorted(findings, key=lambda item: (-RANK[item.severity], item.code, item.path or ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--fail-on", choices=RANK, default="high")
    args = parser.parse_args(argv)
    findings = audit(args.repo_root.resolve())
    report = {
        "schemaVersion": 2,
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
