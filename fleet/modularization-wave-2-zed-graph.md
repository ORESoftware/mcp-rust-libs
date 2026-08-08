# Rust MCP modularization wave 2: Zed dependency-graph servers

Status date: 2026-08-08

Tracking: [GitHub issue #15](https://github.com/ORESoftware/mcp-rust-libs/issues/15), Linear `DEN-957`, `DEN-959`, `DEN-2285`, `DEN-2287`, `DEN-2290`, and `DEN-2293`.

## Why this is a separate wave

The August 2 fleet audit predates four short-name MCP repositories published on August 7. The historical audit remains unchanged; this document and its JSON companion add a dated second wave.

All four repositories began with green Rust CI and the same read-only `zed_dependency_graph` tool, copied graph schema/result construction, hand-written newline-delimited JSON-RPC dispatcher, and MCP revision `2025-06-18`.

The canonical fleet policy is:

- production final revision: `2025-11-25`;
- `2026-07-28`: preview only until final publication and fleet conformance;
- official `rmcp` owns protocol dispatch;
- the shared repository owns generic runtime, safety, contracts, and conformance;
- consumers own organization identity, package coordinates, authorization, business tools, and release decisions.

## Phase A — shared dependency-graph contract: completed

Shared extraction:

- crate: `ore-mcp-zed-graph`;
- shared PR: `ORESoftware/mcp-rust-libs#17`;
- exact-head CI: `31240884725`;
- immutable merge revision: `652eee6538eae8c286b70593d3da574c3da741de`.

The shared crate validates bounded package coordinates, rejects malformed/duplicate/cross-organization graphs, owns the closed-world tool descriptor and standard text-plus-structured result, and centralizes `.vendor/.zed` plus `zed overtake --git-submodules` policy. Product identity and dependency coordinates remain in each consumer.

Consumer evidence:

| Repository | PR | Exact-head CI | Merge commit |
| --- | ---: | ---: | --- |
| `apostille-me/apme-mcp-server.rs` | #3 | `31241191946` | `255b7ae97ecff95725061f422fe9929abc6419f3` |
| `embedded-alerts/eal-mcp-server.rs` | #3 | `31241529326` | `92dd63d223b52f8676eb3a2bd8fb6a3d592fb45b` |
| `evento-globolo/evgl-mcp-server.rs` | #3 | `31241649462` | `81f1a7f346a6bfbb5e1bac35f0f95534e6eb3c6b` |
| `hacker-house-medellin/hhm-mcp-server.rs` | #3 | `31241635908` | `296bd7e8c8eaba28f5683516022759a93c4b7510` |

Every consumer now:

- pins the exact immutable shared revision in `Cargo.toml` and resolver-generated Rust `Cargo.lock`;
- deletes copied generic graph descriptor, output schema, submodule-policy text, and result construction;
- retains only product-owned identity and package coordinates locally;
- rejects non-empty tool arguments fail-closed;
- pins GitHub actions and Rust 1.97.1;
- passes `cargo metadata --locked`, rustfmt, strict Clippy, all-target tests, canonical Zed manifest checks, and Cargo-lock no-drift validation.

The committed Rust `Cargo.lock` proves the shared Rust revision; it is not Zed `.zpkg.lock` provenance.

## Phase B — official runtime and final protocol: open

The consumers still hand-dispatch `initialize`, `ping`, `tools/list`, and `tools/call` and still advertise `2025-06-18`.

Required sequence:

1. complete the narrow `ore-mcp-runtime` work already reserved by `DEN-957`; do not create another shared repository or issue family;
2. use official `rmcp` for stdio lifecycle and protocol dispatch;
3. negotiate final revision `2025-11-25` fail-closed;
4. keep `2026-07-28` preview disabled by default;
5. preserve read-only behavior and the exact six-package product graph;
6. pass shared real-process initialize, closed-world catalog, tool-call, malformed-frame, stdout-purity, byte/frame-bound, cancellation, and shutdown conformance;
7. publish or pin one immutable reviewed runtime revision before consumer migrations.

## Phase C — Zed package provenance: open

For each repository:

1. run authenticated Zed resolution for clients, interfaces, lib, CLI, sync, and shared-auth clients;
2. commit only resolver-generated `.zpkg.lock` provenance;
3. add clean-clone frozen installation;
4. when retained as a gitlink, adopt with `zed overtake --git-submodules` and prove one clean committed path;
5. reject long-name aliases, duplicate identities, and second workspace paths;
6. withhold the `0.1.0` release/tag gate until protocol, conformance, and Zed evidence all pass.

## Non-goals

- moving product package coordinates into the shared repository;
- adding credentials, private schemas, captured MCP payloads, or product business logic;
- introducing another hand-written JSON-RPC protocol stack;
- enabling the `2026-07-28` preview lifecycle by default;
- treating Rust `Cargo.lock` as Zed lock evidence;
- hand-authoring Zed lockfiles or maintaining the same package through two workspace paths.

## Completion evidence

The wave is complete only when phase B and phase C link exact shared and consumer commits and successful runs, final-protocol negotiation passes, stdout remains protocol-pure and bounded, every consumer has resolver-generated Zed lock and frozen-install evidence, and the `0.1.0` release decision is backed by those exact heads.

Machine-readable record: [`modularization-wave-2-zed-graph.json`](modularization-wave-2-zed-graph.json).
