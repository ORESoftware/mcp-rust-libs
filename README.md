# mcp-rust-libs

Canonical shared hardening and conformance infrastructure for ORESoftware's Rust MCP server fleet.

## Initial audit slice

The August 2, 2026 connected-fleet audit found 24 existing standalone Rust MCP repositories and five verified missing servers. The highest-value recurring defects were:

- hand-written JSON-RPC transports pinned to old MCP revisions;
- bearer-authenticated HTTP clients without exact host or redirect policy;
- successful and error response bodies buffered without a pre-buffer byte cap;
- child processes captured through `wait_with_output`, allowing unbounded stdout/stderr memory use;
- stdout log pollution and marker-based rather than semantic JSON-RPC tests.

This first PR extracts four narrow crates under `packages/rust`:

- `ore-mcp-safety` — UTF-8-safe truncation, bounded incremental bytes, error redaction, and header validation;
- `ore-mcp-http` — exact URL parsing, loopback-only HTTP, bearer-host allowlists, and no-redirect defaults;
- `ore-mcp-process` — concurrent bounded stdout/stderr capture with timeout, kill, and reap behavior;
- `ore-mcp-testkit` — semantic JSON-RPC 2.0 stdio audits with byte and frame limits.

Product tools, authorization, mutation gates, credentials, upstream business clients, and domain policy remain in their owning repositories.

## Protocol policy

Production follows the latest final MCP revision (`2025-11-25`). The `2026-07-28` lifecycle remains an opt-in preview until the upstream specification is final and both lifecycle paths pass fleet conformance. Hand-written transports and hard-coded `2024-11-05` servers are migration priorities.

## Validation

```sh
cd packages/rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets

python3 -m unittest -v tooling/test_audit_rust_mcp_server.py
python3 tooling/audit_rust_mcp_server.py --repo-root /path/to/mcp-server
```

Tracking: DEN-957, DEN-959, DEN-965, DEN-779, DEN-852, and DEN-161.
