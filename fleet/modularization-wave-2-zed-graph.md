# Rust MCP modularization wave 2: Zed dependency-graph servers

Status date: 2026-08-08

Tracking: GitHub `ORESoftware/mcp-rust-libs#15` and `#27`; Linear `DEN-957`, `DEN-959`, `DEN-2972`, `DEN-3035`, `DEN-3054`, `DEN-3056`, `DEN-2285`, `DEN-2287`, `DEN-2290`, `DEN-2293`, `DEN-3036`, and `DEN-3060`.

## Result

The four short-name Zed dependency-graph MCP servers have completed both shared graph extraction and official-runtime migration.

All four now:

- pin official `rmcp =2.2.0` exactly;
- pin `ore-mcp-runtime`, `ore-mcp-zed-graph`, and `ore-mcp-testkit` to immutable shared revision `458419497de273d2ca6089a727f38894083d8da6`;
- delegate stdio framing, initialize, ping, notifications, tool dispatch, and unknown-method handling to official `rmcp`;
- compose `ExactProtocol` before SDK negotiation and accept only final MCP `2025-11-25`;
- reject preview `2026-07-28` and legacy `2025-06-18` with generic JSON-RPC `-32600`, no requested-version reflection, and a nonzero failed lifecycle exit;
- expose exactly one closed-world `zed_dependency_graph` tool;
- preserve the product-owned server identity and exact six dependency coordinates;
- accept absent, `null`, and empty-object tool arguments while rejecting non-empty objects, non-object arguments, and unknown tools;
- keep stdout protocol-pure; and
- pass locked hardened CI plus Rust 1.88.0 and Rust 1.97.1 real-process conformance.

Zed registry publication, resolver-generated `.zpkg.lock`, and frozen clean-clone installation remain separate and incomplete. The recursive publication monitor currently reports **0 of 23** packages ready.

## Shared layers

### Product-neutral graph contract

- crate: `ore-mcp-zed-graph`;
- PR: `ORESoftware/mcp-rust-libs#17`;
- exact-head CI: `31240884725`;
- merge revision: `652eee6538eae8c286b70593d3da574c3da741de`.

The crate owns package-coordinate validation, the closed-world tool descriptor, text-plus-structured graph result, `.vendor/.zed` materialization policy, and git-submodule takeover guidance. Consumers retain their organization identity and package coordinates.

### Exact official-runtime boundary

- crate: `ore-mcp-runtime`;
- PR: `ORESoftware/mcp-rust-libs#23`;
- exact head: `58df937a399d792f3695f31abae1490e2b3ac5c5`;
- exact-head CI: `31266779821`;
- merge revision: `458419497de273d2ca6089a727f38894083d8da6`.

`ExactProtocol<S>` validates the initialize request before `rmcp` can normalize or echo a known client-requested version. Existing product handlers remain official `rmcp` services; no parallel protocol stack or second shared repository was introduced.

### External process-crate proof

`file-tunnel-test/mcp-contract-e2e#2` independently consumed the current shared process API. Exact head `af84c37effa1216b80e4a3e1505d80d1d1803d43` passed runs `31267848380` and `31267848386` across Ubuntu 24.04, macOS 14, and Windows 2022 with Rust 1.88.0 and 1.97.1. It proved bounded capture, fail-fast overflow, truncating dual-pipe drain with dropped-byte accounting, and timeout kill/reap behavior.

## Production consumer evidence

| Repository | Runtime issue | PR | Exact head | Merge | Exact-head runs |
| --- | --- | ---: | --- | --- | --- |
| `apostille-me/apme-mcp-server.rs` | `DEN-2972` | #5 | `93eeb4fe4378a3dae6629898a89dd1b19537f984` | `1bffb67aa8ef7fd0fc6b396aff218c6d438fa345` | `31268502539`, `31268502556` |
| `embedded-alerts/eal-mcp-server.rs` | `DEN-3035` | #4 | `b6c11df8821e97a39689e627a443c8e7d2951c74` | `04252a83040f4a95d4ef5bc7aabcd6fd1ba308a4` | `31268928120`, `31268928138` |
| `evento-globolo/evgl-mcp-server.rs` | `DEN-3054` | #4 | `4dae79d6172fdb8aa8e60cc4039edebdd2469ccf` | `7fdb469257496244cf3c6d952acde017cb53f965` | `31269306061`, `31269306081` |
| `hacker-house-medellin/hhm-mcp-server.rs` | `DEN-3056` | #4 | `b236fcc03e69d3a7119e0d44c7b747e93e8ec2ca` | `0adaebe2a46ef055b974f4f9b25d3fcd7df07088` | `31269611106`, `31269611104` |

Each consumer's permanent CI retains:

- committed resolver-generated Rust `Cargo.lock` and no-drift checks;
- exact shared and SDK version assertions;
- rustfmt and strict Clippy;
- direct handler tests;
- child-process accepted-final and rejected-preview/legacy sessions;
- canonical Zed coordinate checks; and
- credential-shaped tracked-content scans.

Rust `Cargo.lock` proves the Rust dependency resolution. It is not Zed lock provenance.

## Matching test-organization evidence

Two connected matching organizations immediately supported independent exact-source execution:

| Production | Test location | PR | Merge | Hosted matrix |
| --- | --- | ---: | --- | --- |
| Embedded Alerts | `embedded-alerts-test/.github` | #9 | `b8f35cf73c6058c6490ab6abee591d767e2f5aa8` | run `31270025607`, six jobs green |
| Evento Globolo | `evento-globolo-test/.github` | #12 | `cf36657662d9ebe422acce04c0744bf6cca486b4` | run `31270107267`, six jobs green |

Each workflow anonymously fetched the exact public production merge commit by full SHA, validated immutable source/shared/SDK/final-protocol/Zed/security invariants, and ran production rustfmt, strict locked Clippy, unit tests, and real-process tests on Ubuntu 24.04, macOS 14, and Windows 2022 with Rust 1.88.0 and 1.97.1.

`apostille-me-test` and `hacker-house-medellin-test` exist but contain no connected repository. Dedicated `mcp-contract-e2e` repositories and GitHub App access for all four matching organizations are tracked by `DEN-3060` and `ORESoftware/mcp-rust-libs#27`. The `.github` proofs above are interim, reviewed evidence, not substitutes for long-term dedicated repository ownership.

## Remaining Zed package gates

The merged publication monitor in `ORESoftware/mcp-rust-libs#26` records the complete recursive closure of 23 packages. Current readiness is **0/23**, with public registry lookups returning HTTP 404.

For each consumer, the remaining sequence is:

1. publish the complete recursive package closure through the reviewed registry path;
2. run authenticated Zed resolution against the six product coordinates and their recursive dependencies;
3. commit only resolver-generated `.zpkg.lock` provenance;
4. pass isolated clean-clone `zed install --frozen`;
5. adopt any retained gitlink with `zed overtake --git-submodules` and prove one canonical package identity and workspace path; and
6. withhold the `0.1.0` release/tag gate until publication, lock, and frozen-install evidence all pass.

Do not hand-author Zed lockfiles, use Rust `Cargo.lock` as Zed evidence, add credentials to source or pull-request workflows, create long-name aliases, or maintain the same package through two workspace paths.

## Qualification

The runtime evidence is direct implementation plus GitHub-hosted compilation and execution. AI Agent Bridge review prompts remain queued in `ORESoftware/ai-agent-bridge.rs#104`, but provider quota is unavailable; no provider-backed ChatGPT/Claude consensus is claimed.

Machine-readable records:

- [`modularization-wave-2-zed-graph.json`](modularization-wave-2-zed-graph.json)
- [`modularization-wave-2-runtime-test-org-provenance.json`](modularization-wave-2-runtime-test-org-provenance.json)
