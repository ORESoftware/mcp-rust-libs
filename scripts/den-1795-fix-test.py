#!/usr/bin/env python3
"""Normalize DEN-1795 path assertions without changing resolver semantics."""

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "packages/rust/crates/ore-mcp-bootstrap/src/lib.rs"
content = path.read_text(encoding="utf-8")
old = '''        assert_eq!(resolved, packaged);
        assert_ne!(resolved, ambient);
'''
new = '''        assert_eq!(
            fs::canonicalize(&resolved).expect("resolved canonical path"),
            fs::canonicalize(&packaged).expect("packaged canonical path")
        );
        assert_ne!(
            fs::canonicalize(&resolved).expect("resolved canonical path"),
            fs::canonicalize(&ambient).expect("ambient canonical path")
        );
'''
count = content.count(old)
if count != 1:
    raise RuntimeError(f"expected one path assertion, found {count}")
path.write_text(content.replace(old, new, 1), encoding="utf-8")
print("DEN-1795 path assertion normalized")
