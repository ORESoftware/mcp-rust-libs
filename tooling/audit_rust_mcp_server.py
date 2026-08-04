#!/usr/bin/env python3
"""Static, fail-closed audit for one Rust MCP server repository.

The scanner emits review signals; it does not pretend source-text matching proves
security. High findings are unsafe-by-default patterns for deployable MCP
servers. Medium findings need an explicit repository-local design review or a
bounded, evidence-backed exception.
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
RMCP_STREAMABLE_HTTP_SECURITY_FLOOR = (1, 4, 0)
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
_CFG_TEST_ATTRIBUTE = re.compile(r"^\s*#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*$")
_WORKFLOW_STEP_START = re.compile(
    r"^(?P<indent>\s*)-\s+(?:name|uses|run|id|if|shell)\s*:",
    re.IGNORECASE,
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


def semver_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
    )


def semver_is_prerelease(value: str) -> bool:
    return bool(
        re.search(
            r"(?<!\d)\d+\.\d+(?:\.\d+)?-[0-9A-Za-z][0-9A-Za-z.-]*",
            value,
        )
    )


def rust_sources(root: Path) -> list[Path]:
    return sorted((root / "src").rglob("*.rs")) if (root / "src").is_dir() else []


def _brace_delta(line: str) -> int:
    """Return a conservative brace delta for a test-only Rust item.

    This is intentionally not a Rust parser. It is used only after an exact
    ``#[cfg(test)]`` attribute to preserve production source that follows the
    test item. Any ambiguous or unterminated test item remains excluded rather
    than allowing later source to be silently trusted.
    """

    return line.count("{") - line.count("}")


def production_text(path: Path) -> str:
    """Return source with exact ``#[cfg(test)]`` items removed.

    The previous implementation truncated the file at the first test attribute,
    allowing production code placed after an inline test module to evade every
    production-only audit. This line-oriented, brace-aware scanner removes only
    the attributed item and then resumes scanning later source.
    """

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    production: list[str] = []
    index = 0
    while index < len(lines):
        if _CFG_TEST_ATTRIBUTE.fullmatch(lines[index]) is None:
            production.append(lines[index])
            index += 1
            continue

        index += 1
        while index < len(lines) and (
            not lines[index].strip() or lines[index].lstrip().startswith("#[")
        ):
            index += 1

        saw_brace = False
        depth = 0
        while index < len(lines):
            line = lines[index]
            if "{" in line:
                saw_brace = True
            depth += _brace_delta(line)
            index += 1
            if saw_brace and depth <= 0:
                break
            if not saw_brace and ";" in line:
                break

    return "\n".join(production)


def workflow_steps(text: str) -> list[str]:
    """Extract YAML step blocks without letting one checkout bless another."""

    lines = text.splitlines()
    starts: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = _WORKFLOW_STEP_START.match(line)
        if match:
            starts.append((index, len(match.group("indent"))))

    steps: list[str] = []
    for position, (start, indent) in enumerate(starts):
        end = len(lines)
        for next_start, next_indent in starts[position + 1 :]:
            if next_indent <= indent:
                end = next_start
                break
        steps.append("\n".join(lines[start:end]))
    return steps


def workflow_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    if not workflows:
        return [Finding("medium", "missing-ci", "no GitHub Actions workflow detected")]
    mutable_action = re.compile(
        r"^\s*(?:-\s+)?uses:\s+[^\s#]+@(?:main|master|v\d+(?:\.\d+)*)\s*$",
        re.MULTILINE,
    )
    checkout = re.compile(r"uses:\s+actions/checkout@", re.IGNORECASE)
    persisted_false = re.compile(
        r"^\s*persist-credentials:\s*(?:false|'false'|\"false\")\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
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
        for step in workflow_steps(text):
            if checkout.search(step) and persisted_false.search(step) is None:
                findings.append(
                    Finding(
                        "low",
                        "checkout-credentials",
                        "a checkout step does not explicitly discard credentials",
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

    streamable_http = any(
        token in combined
        for token in ("transport-streamable-http", "StreamableHttpService", "streamable_http")
    )
    rmcp = dependency_version(dependencies.get("rmcp"))
    if rmcp is None:
        code = "handwritten-jsonrpc" if "jsonrpc" in combined.lower() else "missing-rmcp"
        findings.append(
            Finding(
                "high" if code == "handwritten-jsonrpc" else "medium",
                code,
                "official rmcp transport is not detected",
            )
        )
    else:
        parsed = semver_tuple(rmcp)
        if parsed is None:
            findings.append(
                Finding(
                    "medium",
                    "rmcp-version-unparsed",
                    f"rmcp version requirement {rmcp!r} could not be compared with the security floor",
                )
            )
        elif streamable_http and (
            parsed < RMCP_STREAMABLE_HTTP_SECURITY_FLOOR
            or (
                parsed == RMCP_STREAMABLE_HTTP_SECURITY_FLOOR
                and semver_is_prerelease(rmcp)
            )
        ):
            findings.append(
                Finding(
                    "high",
                    "rmcp-dns-rebinding-floor",
                    f"Streamable HTTP uses rmcp {rmcp!r}; require final >=1.4.0 or a reviewed equivalent Host-validation patch",
                )
            )
        elif parsed < (1, 0, 0):
            findings.append(
                Finding(
                    "medium",
                    "rmcp-prestable",
                    f"rmcp {rmcp!r} is pre-1.0 and needs a reviewed compatibility migration",
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
    proxy_disabled = ".no_proxy()" in production
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
        "schemaVersion": 3,
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
