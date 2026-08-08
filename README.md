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
- `ore-mcp-config` — strict flags2env audit/parsing/coercion with unknown/positional rejection, deterministic source precedence, environment-only secret policy, and value-free diagnostics;
- `ore-mcp-safety` — UTF-8-safe truncation, bounded incremental bytes, error redaction, and header validation;
- `ore-mcp-http` — exact URL parsing, loopback-only HTTP, bearer-host allowlists, no-redirect defaults, and incremental response-body bounds;
- `ore-mcp-process` — fail-fast or truncating concurrent stdout/stderr capture with timeout, kill, and reap behavior;
- `ore-mcp-runtime` — official `rmcp` stdio lifecycle plus exact final-protocol enforcement before SDK negotiation;
- `ore-mcp-testkit` — semantic JSON-RPC 2.0 stdio, initialize, catalog, result, byte/frame-limit, and stdout-purity audits;
- `ore-mcp-zed-graph` — bounded package-coordinate validation plus the shared closed-world dependency-graph descriptor and result contract.

The bootstrap, config, and HTTP layers intentionally avoid a hidden fleet-wide `rmcp`, OpenTelemetry, or concrete HTTP-client upgrade. Servers in different SDK and OpenTelemetry cohorts can share policy without sharing product dependencies.

Product tools, authorization, mutation gates, credentials, upstream business clients, concrete exporters, client timeouts, package coordinates, and domain policy remain in their owning repositories.

## API documentation and MCP discovery

[`contracts/api-docs/contract-v1.md`](contracts/api-docs/contract-v1.md) defines the
framework-neutral `ore.api-docs.v1` contract for every fleet API server and its
organization-level `*-mcp-server.rs` counterpart. The standard fixes the public
discovery, OpenAPI, compatibility-alias, and browser-UI routes; separates
authenticated internal docs; and requires five read-only MCP documentation
tools without granting arbitrary API execution.

The standard-library-only validator proves exact OpenAPI response-byte SHA-256
parity, OpenAPI 3.1 metadata, stable unique operation IDs, public/internal
separation, same-organization API/MCP pairing, and fail-closed mutation
classification. The checked-in schema and fixtures let Rust, Node, Dart, Gleam,
and mixed-language repositories consume the same gate.

```sh
python3 tooling/validate_api_docs_contract.py \
  --manifest contracts/api-docs/example.manifest.json \
  --openapi contracts/api-docs/example.openapi.json \
  --expected-mcp-repository example/example-mcp-server.rs \
  --operations

python3 -m unittest -v tooling/test_validate_api_docs_contract.py
```

Tracking: DEN-3158.

## First ten-server migration wave

The initial consumer wave is:

1. `benefactor-cc/benefactor-cc-mcp-server.rs`
2. `sonus-auris/sonus-auris-mcp-server.rs`
3. `fiducia-cloud/fiducia-mcp-server.rs`
4. `quaestor-ledger/quaestor-ledger-mcp-server.rs`
5. `daedalus-fab/daedalus-fab-mcp-server.rs`
6. `athlet-o/athleto-mcp-server.rs`
7. `3FA-app/3FA-mcp-server.rs`
8. `akrion-sim/akrion-mcp-server.rs`
9. `discrete-event-systems/des-mcp-server.rs`
10. `scintilla-run/scintilla-mcp-server.rs`

`usa-acc/usa-acc-mcp-server.rs` was removed from this bootstrap wave after source inspection showed that its `src/telemetry.rs` is a product Supabase telemetry client rather than the repeated process-OpenTelemetry bootstrap. It remains eligible for a later HTTP/body-policy migration.

See [`fleet/modularization-wave-1.md`](fleet/modularization-wave-1.md) for ownership boundaries, dependency order, and per-repository validation requirements.

## Zed dependency-graph migration wave

A dated second wave covers four short-name servers published after the August 2 inventory:

1. `apostille-me/apme-mcp-server.rs`
2. `embedded-alerts/eal-mcp-server.rs`
3. `evento-globolo/evgl-mcp-server.rs`
4. `hacker-house-medellin/hhm-mcp-server.rs`

All four now use exact official `rmcp 2.2.0`, the shared runtime and graph contract, and final MCP `2025-11-25`. Each passed locked hardened CI plus Rust 1.88.0 and 1.97.1 real-process conformance, including generic rejection of preview `2026-07-28` and legacy `2025-06-18` before SDK normalization.

Independent matching test-organization matrices also execute the exact Embedded Alerts and Evento Globolo production merges on Linux, macOS, and Windows. Dedicated test repositories for all four matching organizations remain tracked separately.

Zed package provenance is not complete: the recursive publication monitor currently reports zero of 23 packages ready, so resolver-generated `.zpkg.lock` and isolated `zed install --frozen` evidence remain blocked on publication rather than runtime correctness.

See [`fleet/modularization-wave-2-zed-graph.md`](fleet/modularization-wave-2-zed-graph.md), its [machine-readable record](fleet/modularization-wave-2-zed-graph.json), and the [test-organization provenance ledger](fleet/modularization-wave-2-runtime-test-org-provenance.md). The historical August 2 inventory remains unchanged.

## Protocol policy

Production follows final MCP `2025-11-25`. Preview `2026-07-28` remains disabled until upstream finalization and explicit conformance. New migrations use official SDK dispatch and an exact protocol boundary rather than hand-written transports or negotiated-version normalization.

## Validation

```sh
cd packages/rust
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo doc --locked --workspace --no-deps

python3 -m unittest -v \
  tooling/test_audit_rust_mcp_server.py \
  tooling/test_check_deployable_lockfile.py \
  tooling/test_check_fleet_pr_evidence.py \
  tooling/test_check_wave2_evidence.py \
  tooling/test_validate_api_docs_contract.py
python3 tooling/audit_rust_mcp_server.py --repo-root /path/to/mcp-server
python3 tooling/check_wave2_evidence.py
```

Tracking: DEN-957, DEN-959, DEN-960, DEN-965, DEN-779, DEN-852, DEN-161, DEN-3081, and DEN-3158.
