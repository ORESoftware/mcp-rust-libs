# Rust MCP modularization wave 2: Zed dependency-graph servers

Status date: 2026-08-08

Tracking: [GitHub issue #15](https://github.com/ORESoftware/mcp-rust-libs/issues/15), Linear `DEN-957`, `DEN-959`, `DEN-2285`, `DEN-2287`, `DEN-2290`, and `DEN-2293`.

## Why this is a separate wave

The August 2 fleet audit predates four short-name MCP repositories published on August 7. The historical audit remains unchanged; this document and its JSON companion add a dated second wave.

All four repositories have green initial Rust CI, expose the same read-only `zed_dependency_graph` tool, and repeat the same newline-delimited JSON-RPC dispatcher and graph schema:

| Repository | Current head | Push CI |
| --- | --- | --- |
| `apostille-me/apme-mcp-server.rs` | `7ab3198e78ce30849c22584ac9afb5007d3ed2ab` | `31228575090` |
| `embedded-alerts/eal-mcp-server.rs` | `05384988c517b19e49022d32945a11c3393de0e4` | `31228579616` |
| `evento-globolo/evgl-mcp-server.rs` | `6e69697b525ce696f98a8e74b35c888487240796` | `31228583825` |
| `hacker-house-medellin/hhm-mcp-server.rs` | `9e8850ff7b48b41f46ff62af31ca4d423e5aa7d5` | `31228588520` |

Initial CI proves formatting, strict Clippy, unit tests, and manifest-content checks. It does not yet prove shared-runtime adoption, final-protocol negotiation, authenticated Zed resolution, resolver-generated lock provenance, or frozen clean-clone installation.

## Exact drift

Each consumer currently hard-codes MCP revision `2025-06-18` and manually dispatches `initialize`, `ping`, `tools/list`, and `tools/call`.

The canonical fleet policy is:

- production final revision: `2025-11-25`;
- `2026-07-28`: preview only until final publication and fleet conformance;
- official `rmcp` owns protocol dispatch;
- the shared repository owns generic runtime, safety, contracts, and conformance;
- consumers own organization identity, package coordinates, authorization, business tools, and release decisions.

## Shared-layer sequence

1. Complete the narrow `ore-mcp-runtime` and generic contract work already reserved by `DEN-957`; do not create another shared repository or a second issue family.
2. Keep SDK/version boundaries explicit so the runtime migration does not force unrelated OpenTelemetry or HTTP-client upgrades.
3. Represent the Zed dependency graph with a generic DTO/tool contract. Package coordinates and server titles remain consumer configuration.
4. Extend `ore-mcp-testkit` with real-process initialization, closed-world tool-catalog, tool-call result, stdout-purity, malformed-frame, lifecycle, and byte/frame-bound checks.
5. Publish or pin one immutable reviewed shared revision before opening consumer migrations.

## Consumer sequence

For each repository:

1. replace the copied protocol dispatcher with official `rmcp` integration;
2. replace copied generic graph DTO/schema/result construction with the shared contract;
3. negotiate the final `2025-11-25` lifecycle and reject unsupported versions fail-closed;
4. preserve read-only behavior, the exact six-package graph, and the organization-specific server identity;
5. run the shared semantic conformance harness against the built process;
6. run authenticated Zed resolution and commit only resolver-generated `.zpkg.lock` provenance;
7. add clean-clone frozen installation;
8. when the repository is retained as a gitlink, adopt it with `zed overtake --git-submodules` and prove one clean committed path;
9. withhold the `0.1.0` release/tag gate until all exact-head evidence passes.

## Non-goals

- moving product package coordinates into the shared repository;
- adding credentials, private schemas, captured MCP payloads, or product business logic;
- introducing another hand-written JSON-RPC protocol stack;
- enabling the `2026-07-28` preview lifecycle by default;
- hand-authoring Zed lockfiles or maintaining the same package through two workspace paths.

## Completion evidence

The wave is complete only when the shared PR and all four consumer PRs link exact commits and successful runs, copied generic dispatch/schema code is deleted, final-protocol negotiation passes, stdout remains protocol-pure and bounded, and every consumer has resolver-generated Zed lock and frozen-install evidence.

Machine-readable record: [`modularization-wave-2-zed-graph.json`](modularization-wave-2-zed-graph.json).
