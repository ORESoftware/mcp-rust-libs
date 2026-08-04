# mcp-rust-libs

Canonical shared hardening and conformance infrastructure for ORESoftware's Rust MCP server fleet.

## Fleet audit

The August 2, 2026 connected-fleet audit found 24 existing standalone Rust MCP repositories and five verified missing servers. The highest-value recurring defects were:

- hand-written JSON-RPC transports pinned to old MCP revisions;
- bearer-authenticated HTTP clients without exact host or redirect policy;
- successful and error response bodies buffered without a pre-buffer byte cap;
- child processes captured through `wait_with_output`, allowing unbounded stdout/stderr memory use;
- stdout log pollution and marker-based rather than semantic JSON-RPC tests;
- copied startup flag discovery, telemetry attribute filtering, transport identity, and server bootstrap code drifting independently across repositories.

## Shared Rust crates

The `packages/rust` workspace contains narrow, version-neutral infrastructure:

- `ore-mcp-bootstrap` — strict startup-config discovery, secret-free option redaction, bounded telemetry resource-attribute policy, and validated server/transport identity;
- `ore-mcp-safety` — UTF-8-safe truncation, bounded incremental bytes, error redaction, and header validation;
- `ore-mcp-http` — exact URL parsing, loopback-only HTTP, bearer-host allowlists, no-redirect defaults, and incremental response-body bounds;
- `ore-mcp-process` — concurrent bounded stdout/stderr capture with timeout, kill, and reap behavior;
- `ore-mcp-testkit` — semantic JSON-RPC 2.0 stdio audits with byte and frame limits.

The bootstrap and HTTP layers intentionally do not depend on a particular `rmcp`, OpenTelemetry, or concrete HTTP-client version. Servers in the OpenTelemetry 0.27 and 0.32 cohorts can share policy without a hidden fleet-wide SDK upgrade.

Product tools, authorization, mutation gates, credentials, upstream business clients, concrete exporters, client timeouts, and domain policy remain in their owning repositories.

## First ten-server migration wave

The initial consumer wave is:

1. `benefactor-cc/benefactor-cc-mcp-server.rs`
2. `sonus-auris/sonus-auris-mcp-server.rs`
3. `fiducia-cloud/fiducia-mcp-server.rs`
4. `quaestor-ledger/quaestor-ledger-mcp-server.rs`
5. `daedalus-fab/daedalus-fab-mcp-server.rs`
6. `athlet-o/athleto-mcp-server.rs`
7. `usa-acc/usa-acc-mcp-server.rs`
8. `akrion-sim/akrion-mcp-server.rs`
9. `discrete-event-systems/des-mcp-server.rs`
10. `scintilla-run/scintilla-mcp-server.rs`

See [`fleet/modularization-wave-1.md`](fleet/modularization-wave-1.md) for ownership boundaries, dependency order, and per-repository validation requirements.

## Protocol policy

Production follows the latest final MCP revision (`2025-11-25`). The `2026-07-28` lifecycle remains an opt-in preview until the upstream specification is final and both lifecycle paths pass fleet conformance. Hand-written transports and hard-coded `2024-11-05` servers are migration priorities.

## Validation

```sh
cd packages/rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo doc --workspace --no-deps

python3 -m unittest -v tooling/test_audit_rust_mcp_server.py
python3 tooling/audit_rust_mcp_server.py --repo-root /path/to/mcp-server
```

Tracking: DEN-957, DEN-959, DEN-965, DEN-779, DEN-852, DEN-161, and DEN-1248.
