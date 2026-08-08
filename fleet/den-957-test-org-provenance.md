# DEN-957 test-organization provenance extension

**Updated:** 2026-08-08 (America/New_York)  
**Parent Linear issue:** `DEN-957`  
**Shared bootstrap revision:** `a5c1ba9c50493ac625dd2fb175af21263d0d2801`

This ledger supplements `modularization-wave-1-completion.md`. It records the
follow-up test-organization work without changing the canonical production PR
or merge records.

## Result

Six of the ten wave-1 servers now have credential-free, byte-exact source
provenance harnesses in matching `*-test` organizations, and all six harnesses
have a successful GitHub Actions pull-request run. Five use their existing
`mcp-contract-e2e` repositories. Discrete Event Systems had no dedicated MCP
contract repository, so its harness is isolated under
`discrete-event-systems-test/.github/contract-tests/des-mcp-server/`; the two
browser E2E repositories were not changed.

| Production server | Production head captured | Test location | Test PR | Test merge | Successful hosted validation |
|---|---|---|---:|---|---|
| `3FA-app/3FA-mcp-server.rs` | `82ef416159e0cfef007aa18a1b58b15e6bd17580` | `3fa-app-test/mcp-contract-e2e` | [#3](https://github.com/3fa-app-test/mcp-contract-e2e/pull/3) | `7004562817cd148bcab76aba10c806161561975b` | [run 31240464773](https://github.com/3fa-app-test/mcp-contract-e2e/actions/runs/31240464773) |
| `fiducia-cloud/fiducia-mcp-server.rs` | `430ed9c69eae0fd2b446aa8564f45cc17d59069b` | `fiducia-cloud-test/mcp-contract-e2e` | [#2](https://github.com/fiducia-cloud-test/mcp-contract-e2e/pull/2) | `e98f61298eebcd0a25c8cd294be9ab50bf550954` | [run 31240622986](https://github.com/fiducia-cloud-test/mcp-contract-e2e/actions/runs/31240622986) |
| `quaestor-ledger/quaestor-ledger-mcp-server.rs` | `378b676feb39e0a36e87926daf0835a459a419d1` | `quaestor-ledger-test/mcp-contract-e2e` | [#2](https://github.com/quaestor-ledger-test/mcp-contract-e2e/pull/2) | `56ddf7c4ba7907ada119cd3d3dc8c40b6c988e71` | [run 31240751011](https://github.com/quaestor-ledger-test/mcp-contract-e2e/actions/runs/31240751011) |
| `sonus-auris/sonus-auris-mcp-server.rs` | `56086f0525659fe5af2ac59601199eae1db5b18c` | `sonus-auris-test/mcp-contract-e2e` | [#2](https://github.com/sonus-auris-test/mcp-contract-e2e/pull/2) | `54028daea857d67b1b851850c2df5b5f7d8f2b01` | [run 31241061769](https://github.com/sonus-auris-test/mcp-contract-e2e/actions/runs/31241061769) |
| `scintilla-run/scintilla-mcp-server.rs` | `45f87bdc670214b0d00dab5e7222b45fad5302d1` | `scintilla-run-test/mcp-contract-e2e` | [#3](https://github.com/scintilla-run-test/mcp-contract-e2e/pull/3) | `9d99856baf44584ab7a2bbc5116dbe724524fc7c` | [run 31241212743](https://github.com/scintilla-run-test/mcp-contract-e2e/actions/runs/31241212743) |
| `discrete-event-systems/des-mcp-server.rs` | `fa430d5257e2679c7c732d97503a28ffba18d3f6` | `discrete-event-systems-test/.github/contract-tests/des-mcp-server` | [#6](https://github.com/discrete-event-systems-test/.github/pull/6) | `34ef5334f9c115e66627bec719ddb5a96e6a3881` | [run 31241357736](https://github.com/discrete-event-systems-test/.github/actions/runs/31241357736) |

## Contract enforced by every harness

Each harness records the production repository and an immutable production
commit, then stores byte-exact snapshots of:

- `Cargo.toml`;
- `src/telemetry.rs`;
- `tests/shared_bootstrap_contract.rs`.

`shared-bootstrap-provenance.json` records the production Git blob SHA for each
snapshot. The Node verifier recomputes Git blob IDs and rejects any mismatch. It
also verifies that:

- `ore-mcp-bootstrap` is pinned to the exact shared revision;
- static stdio identity is validated by
  `ore_mcp_bootstrap::runtime::ServerIdentity::stdio`;
- version-neutral resource-attribute parsing is delegated to
  `ore_mcp_bootstrap::telemetry::resource_attribute_pairs`;
- MCP logs remain on stderr;
- local copies of shared sensitive-key policy are absent;
- fixture paths cannot escape the fixture directory;
- credential-shaped values are absent from source snapshots and metadata;
- pull-request workflows use read-only contents access and do not persist
  checkout credentials.

Product-owned behavior remains visible in the exact snapshots. For example,
Fiducia retains collector and attribute caps, while Sonus retains the approved
100-hour local-retention metadata contract.

## Hosted validation qualification

All six pull-request workflows completed successfully and executed the
credential-free provenance verifier. These runs validate the fixture Git blob
IDs, immutable source and shared-library pins, policy-delegation assertions,
fixture path restrictions, and credential-shape scan. They do not claim to
compile the private production repositories inside the test organization.
Production compilation and Rust tests remain recorded separately in the wave-1
completion evidence.

## Remaining test-organization gaps

The following matching organizations returned 404 during the 2026-08-08
reconciliation, so no matching test repository could be created through the
connected GitHub App:

- `benefactor-cc-test` for `benefactor-cc/benefactor-cc-mcp-server.rs`;
- `daedalus-fab-test` for `daedalus-fab/daedalus-fab-mcp-server.rs`;
- `athlet-o-test` for `athlet-o/athleto-mcp-server.rs`;
- `akrion-sim-test` for `akrion-sim/akrion-mcp-server.rs`.

Creation and GitHub App installation are tracked in
[issue #20](https://github.com/ORESoftware/mcp-rust-libs/issues/20). No
substitute production mutation or credential-bearing pull-request workflow was
introduced.

## Related registries

- Production completion: `modularization-wave-1-completion.md`
- GitHub organization and Project routing: `github-org-projects.md`
- Linear project routing: `linear-projects.md`
- Machine-readable test evidence: `den-957-test-org-provenance.json`
- Missing test-organization follow-up: [issue #20](https://github.com/ORESoftware/mcp-rust-libs/issues/20)
