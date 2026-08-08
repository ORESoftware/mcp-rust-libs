# Wave-2 MCP runtime test-organization provenance

**Updated:** 2026-08-08  
**Parent:** Linear `DEN-957`  
**Shared runtime revision:** `458419497de273d2ca6089a727f38894083d8da6`

This ledger records independent execution evidence for the four official-`rmcp` Zed dependency-graph consumer migrations. It complements the production evidence in `modularization-wave-2-zed-graph.md` and does not convert runtime proof into Zed package provenance.

## Security model

The matching test workflows:

- fetch public production source anonymously by full 40-character commit SHA;
- use read-only contents permissions;
- do not persist checkout credentials;
- pin every GitHub Action by immutable SHA;
- validate exact production, shared-runtime, SDK, protocol, and Zed-coordinate invariants before compilation;
- scan tracked production source for credential-shaped content; and
- use no production GitHub PAT, Linear token, Cloudflare token, R2 credential, product secret, or provider key.

## Shared process consumer

`file-tunnel-test/mcp-contract-e2e#2` is an external consumer of the shared process crate. Exact head `af84c37effa1216b80e4a3e1505d80d1d1803d43` merged as `1f68e7b6d1d2b00e292f5abecca03e012a0c121c` after runs `31267848380` and `31267848386` passed.

The six-job Ubuntu/macOS/Windows × Rust 1.88.0/1.97.1 matrix proved:

- bounded small stdout and stderr capture;
- fail-fast output overflow;
- truncating dual-pipe drain with exact dropped-byte accounting;
- timeout kill and reap behavior;
- rustfmt and strict Clippy in an external crate.

## Matching wave-2 organizations

### Embedded Alerts — complete interim proof

- production merge: `embedded-alerts/eal-mcp-server.rs@04252a83040f4a95d4ef5bc7aabcd6fd1ba308a4`;
- test location: `embedded-alerts-test/.github`;
- PR: `#9`;
- exact head: `3c33af2bfe65f5834c1c5e2cee4d0cad0672152b`;
- merge: `b8f35cf73c6058c6490ab6abee591d767e2f5aa8`;
- run: `31270025607`;
- result: all six Ubuntu 24.04, macOS 14, and Windows 2022 jobs passed on Rust 1.88.0 and 1.97.1.

Each job anonymously fetched the exact production merge, validated `rmcp =2.2.0`, shared revision `458419497de273d2ca6089a727f38894083d8da6`, final `2025-11-25` protocol enforcement, exact `eal-*` Zed coordinates, absence of a temporary materializer, and tracked-source credential hygiene. It then ran production rustfmt, strict locked Clippy, unit tests, and real-process accepted-final and rejected-preview/legacy sessions.

### Evento Globolo — complete interim proof

- production merge: `evento-globolo/evgl-mcp-server.rs@7fdb469257496244cf3c6d952acde017cb53f965`;
- test location: `evento-globolo-test/.github`;
- PR: `#12`;
- exact head: `be46073da6d3fabbda9e445fad8c67fdf1b9c2dd`;
- merge: `cf36657662d9ebe422acce04c0744bf6cca486b4`;
- run: `31270107267`;
- result: all six Ubuntu 24.04, macOS 14, and Windows 2022 jobs passed on Rust 1.88.0 and 1.97.1.

The contract mirrors Embedded Alerts while requiring the exact Evento Globolo production merge and `evgl-*` Zed coordinates.

### Apostille Me — dedicated repository blocked

`apostille-me-test` exists but has no connected repository. No substitute credential-bearing workflow was added. The production runtime remains fully green in `apostille-me/apme-mcp-server.rs#5`; dedicated matching-org repository and App provisioning are tracked by Linear `DEN-3060` and GitHub `ORESoftware/mcp-rust-libs#27`.

### Hacker House Medellín — dedicated repository blocked

`hacker-house-medellin-test` exists but has no connected repository. The production runtime remains fully green in `hacker-house-medellin/hhm-mcp-server.rs#4`; dedicated matching-org repository and App provisioning share the same `DEN-3060` / GitHub `#27` follow-up.

## Administrative follow-up

The long-term target is one dedicated `mcp-contract-e2e` repository in each of the four matching organizations. The two `.github` workflows are reviewed interim proofs and must receive an explicit retention or supersession trace when dedicated repositories exist.

Required provisioning:

1. install or extend the connected GitHub App in all four organizations;
2. create public `mcp-contract-e2e` repositories with `main` default branches;
3. port the exact-source six-job runtime matrix;
4. keep anonymous exact-SHA production fetches and read-only credentials policy; and
5. add Zed frozen-install stages only after the registry monitor reports the full closure available.

## Qualification boundary

This evidence proves source identity, dependency/runtime policy, cross-platform compilation, and executable MCP conformance. It does **not** prove:

- Zed registry publication;
- a resolver-generated `.zpkg.lock`;
- isolated `zed install --frozen`;
- deployment behavior; or
- provider-backed AI review consensus.

The publication monitor remains **0/23 ready** under `DEN-3036`, so frozen installation is not yet executable. AI Agent Bridge prompts remain queued in `ORESoftware/ai-agent-bridge.rs#104`; provider quota is unavailable, and no ChatGPT/Claude consensus is claimed.

Machine-readable record: [`modularization-wave-2-runtime-test-org-provenance.json`](modularization-wave-2-runtime-test-org-provenance.json).
