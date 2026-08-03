#!/usr/bin/env python3
"""Fail closed when a deployable Rust MCP server lacks tracked dependency state."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Result:
    ok: bool
    code: str
    message: str


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def is_deployable_package(root: Path) -> bool:
    manifest_path = root / "Cargo.toml"
    if not manifest_path.is_file():
        return False
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("package")
    if not isinstance(package, dict):
        return False
    # Standalone MCP repositories are applications even when they also expose a
    # library target. `publish = false` does not make dependency state optional.
    return (root / "src/main.rs").is_file() or isinstance(manifest.get("bin"), list)


def check(root: Path) -> Result:
    root = root.resolve()
    if not is_deployable_package(root):
        return Result(True, "not-deployable", "repository is not a deployable Rust package")

    lockfile = root / "Cargo.lock"
    if not lockfile.is_file():
        return Result(False, "missing-lockfile", "deployable Rust MCP server must commit Cargo.lock")

    ignored = run_git(root, "check-ignore", "--no-index", "-q", "Cargo.lock")
    if ignored.returncode == 0:
        return Result(False, "ignored-lockfile", "Cargo.lock is ignored by repository rules")
    if ignored.returncode not in {1}:
        return Result(
            False,
            "git-check-ignore-failed",
            f"git check-ignore failed: {ignored.stderr.strip() or ignored.stdout.strip()}",
        )

    tracked = run_git(root, "ls-files", "--error-unmatch", "Cargo.lock")
    if tracked.returncode != 0:
        return Result(False, "untracked-lockfile", "Cargo.lock exists but is not tracked by Git")

    try:
        lock = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return Result(False, "invalid-lockfile", f"Cargo.lock is not valid TOML: {error}")
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        return Result(False, "empty-lockfile", "Cargo.lock contains no resolved packages")

    return Result(True, "tracked-lockfile", "Cargo.lock exists, is valid, and is tracked")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = check(args.repo_root)
    if args.json:
        print(json.dumps(asdict(result), sort_keys=True))
    else:
        stream = sys.stdout if result.ok else sys.stderr
        print(f"{result.code}: {result.message}", file=stream)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
