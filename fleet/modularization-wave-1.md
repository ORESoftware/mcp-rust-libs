# Rust MCP modularization wave 1

Date: 2026-08-04  
Tracking: DEN-957, DEN-959, DEN-965, DEN-1248

## Goal

Migrate ten mature standalone Rust MCP servers from repository-local copies of
startup, telemetry-policy, HTTP-body, safety, and process infrastructure to one
immutable revision of `ORESoftware/mcp-rust-libs`.

This wave is an infrastructure extraction, not a product rewrite. Tool names,
JSON schemas, authorization, read/write policy, upstream business clients, and
domain behavior must remain stable unless a separately documented bug requires
a change.

## Selection criteria

The connected fleet has 24 existing standalone Rust MCP repositories. The first
ten were selected because they combine:

- repeated stdio bootstrap and OpenTelemetry resource-policy code;
- repeated bounded HTTP readers and subprocess wrappers;
- mature hardening/test lanes, reducing migration ambiguity;
- meaningful process, proxy, database, cluster, or external-service surfaces;
- representation of both OpenTelemetry 0.27 and 0.32 cohorts.

## Selected repositories

| Order | Repository | OTEL cohort | First shared surface | Migration status |
| ---: | --- | --- | --- | --- |
| 1 | `benefactor-cc/benefactor-cc-mcp-server.rs` | 0.32 | config, telemetry policy, identity, HTTP body | queued after library merge |
| 2 | `sonus-auris/sonus-auris-mcp-server.rs` | 0.27 | telemetry policy, identity, HTTP body | queued after library merge |
| 3 | `fiducia-cloud/fiducia-mcp-server.rs` | 0.27 | telemetry policy, identity, HTTP body | queued after library merge |
| 4 | `quaestor-ledger/quaestor-ledger-mcp-server.rs` | 0.27 | telemetry policy, identity, HTTP body | stack after hardening PR #6 |
| 5 | `daedalus-fab/daedalus-fab-mcp-server.rs` | 0.27 | telemetry policy, identity, HTTP body | queued after library merge |
| 6 | `athlet-o/athleto-mcp-server.rs` | 0.27 | config, telemetry policy, identity, HTTP body | queued after library merge |
| 7 | `usa-acc/usa-acc-mcp-server.rs` | 0.27 | telemetry policy, identity, HTTP body | queued after library merge |
| 8 | `akrion-sim/akrion-mcp-server.rs` | 0.32 | telemetry policy, identity, HTTP body | queued after library merge |
| 9 | `discrete-event-systems/des-mcp-server.rs` | 0.32 | telemetry policy, identity, HTTP body | queued after library merge |
| 10 | `scintilla-run/scintilla-mcp-server.rs` | 0.27 | telemetry policy, identity, HTTP body | queued after library merge |

## Shared versus product-owned boundaries

### Shared

- reviewed startup configuration search order;
- path and log-filter prevalidation;
- command-line option-name redaction;
- standard telemetry environment mappings;
- bounded, secret-free OTEL resource-attribute parsing;
- canonical service/namespace/transport identity;
- endpoint and bearer-host policy;
- incremental HTTP response-body ceilings;
- bounded subprocess capture and timeout/reap behavior;
- semantic stdio JSON-RPC conformance helpers.

### Product-owned

- MCP tools, resources, prompts, schemas, and descriptions;
- authorization and mutation gates;
- secret lookup and credential scope;
- upstream API clients and exact endpoint allowlists;
- concrete `reqwest`, `rmcp`, and OpenTelemetry SDK versions;
- exporter/provider construction and shutdown;
- repository, cluster, database, business, and product policy;
- tool-specific timeout and response-size choices within shared bounds.

## Dependency and merge order

1. Merge `ORESoftware/mcp-rust-libs` bootstrap/HTTP PR after Rust 1.88 and 1.97
   formatting, Clippy, unit, adversarial, and documentation jobs pass.
2. Pin every consumer to that exact merge commit, never a branch or moving tag.
3. Regenerate and commit each consumer `Cargo.lock` from the exact branch state.
4. Run each repository's existing locked CI, architecture tests, and stdio
   integration suite.
5. Merge consumer PRs only when the pinned shared commit is on `main`, the head
   is green and mergeable, and there are no unresolved review requests.
6. Update this table and Linear after each merge.

No consumer may depend on the unmerged shared-library branch.

## Per-repository acceptance checks

Every consumer PR must prove:

- the dependency uses an exact 40-hex Git revision;
- `Cargo.lock` resolves that same revision;
- product tool names and count are unchanged, unless explicitly documented;
- stdout remains reserved for MCP JSON-RPC;
- resource attributes cannot expose secret-like values or override canonical
  service identity;
- HTTP bodies fail before unbounded buffering;
- bearer clients retain exact-host and no-redirect policy;
- subprocess output remains bounded, timed out, killed, and reaped;
- formatting, strict Clippy, tests, release build, audit, architecture, and stdio
  checks required by that repository remain green.

## Out of scope for wave 1

- upgrading all servers to one OpenTelemetry release;
- changing MCP protocol lifecycle policy;
- replacing official `rmcp` transports;
- moving product-specific clients or schemas into the shared repository;
- creating a monorepo or Git submodules;
- auto-merging a consumer whose dependency or CI evidence is incomplete.
