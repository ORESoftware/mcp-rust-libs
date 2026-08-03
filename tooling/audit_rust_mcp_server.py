#!/usr/bin/env python3
"""Static, fail-closed audit for one Rust MCP server repository."""

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


def audit(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    cargo = root / "Cargo.toml"
    manifest = tomllib.loads(cargo.read_text(encoding="utf-8")) if cargo.is_file() else {}
    dependencies = manifest.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}
    sources = sorted((root / "src").rglob("*.rs")) if (root / "src").is_dir() else []
    combined = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in sources)
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
            findings.append(Finding("medium", "rmcp-major", f"rmcp {rmcp!r} requires a reviewed 3.x migration"))

    for version in STALE_PROTOCOLS:
        if version in combined:
            findings.append(Finding("high" if version == "2024-11-05" else "medium", "stale-protocol", f"source hard-codes MCP {version}"))

    patterns = (
        (r"\.wait_with_output\s*\(", "high", "unbounded-subprocess-output", "wait_with_output buffers complete child output"),
        (r"\.output\s*\(\s*\)", "medium", "unbounded-subprocess-output", "Command::output may buffer unbounded child output"),
        (r"\.text\s*\(\s*\)", "medium", "unbounded-http-body", "response text is buffered without an obvious cap"),
        (r"\.json(?:\s*::[^\(]+)?\s*\(\s*\)", "medium", "unbounded-http-body", "response JSON is buffered without an obvious cap"),
        (r"\b(?:print|println)!\s*\(", "high", "stdout-pollution", "stdout writes can corrupt MCP stdio"),
    )
    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        production = text.split("#[cfg(test)]", 1)[0]
        for pattern, severity, code, message in patterns:
            if re.search(pattern, production):
                findings.append(Finding(severity, code, message, path.relative_to(root).as_posix()))

    bearer = ".bearer_auth(" in combined or "AUTHORIZATION" in combined
    redirect_denied = any(token in combined for token in ("Policy::none", "redirect::Policy::none", "RedirectPolicy::None"))
    if bearer and not redirect_denied:
        findings.append(Finding("high", "bearer-redirect-policy", "bearer client lacks an obvious redirect-denial policy"))
    if not (root / "Cargo.lock").is_file():
        findings.append(Finding("low", "missing-lock", "Cargo.lock is absent for a deployable server"))
    if not list((root / ".github/workflows").glob("*.y*ml")):
        findings.append(Finding("medium", "missing-ci", "no GitHub Actions workflow detected"))
    if "#[cfg(test)]" not in combined and not (root / "tests").is_dir():
        findings.append(Finding("medium", "missing-tests", "no Rust tests detected"))
    return sorted(findings, key=lambda item: (-RANK[item.severity], item.code, item.path or ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--fail-on", choices=RANK, default="high")
    args = parser.parse_args(argv)
    findings = audit(args.repo_root.resolve())
    report = {
        "schemaVersion": 1,
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
