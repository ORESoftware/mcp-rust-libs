# Linear project registry — Rust MCP wave 1

**Updated:** 2026-08-07  
**Parent issue:** DEN-957

| GitHub organization | Canonical Linear project | Server repository | Parent | Canonical PR |
|---|---|---|---|---|
| `benefactor-cc` | [github.com/benefactor-cc](https://linear.app/denman/project/githubcombenefactor-cc-6bef502a1ef0) | `benefactor-cc/benefactor-cc-mcp-server.rs` | DEN-957 | [PR #18](https://github.com/benefactor-cc/benefactor-cc-mcp-server.rs/pull/18) |
| `sonus-auris` | [github.com/sonus-auris](https://linear.app/denman/project/githubcomsonus-auris-a557165528ef) | `sonus-auris/sonus-auris-mcp-server.rs` | DEN-957 | [PR #15](https://github.com/sonus-auris/sonus-auris-mcp-server.rs/pull/15) |
| `fiducia-cloud` | [fiducia-cloud](https://linear.app/denman/project/fiducia-cloud-8fd5e1bec9d3) | `fiducia-cloud/fiducia-mcp-server.rs` | DEN-957 | [PR #16](https://github.com/fiducia-cloud/fiducia-mcp-server.rs/pull/16) |
| `quaestor-ledger` | [github.com/quaestor-ledger](https://linear.app/denman/project/githubcomquaestor-ledger-a8cd440b3acc) | `quaestor-ledger/quaestor-ledger-mcp-server.rs` | DEN-957 | [PR #11](https://github.com/quaestor-ledger/quaestor-ledger-mcp-server.rs/pull/11) |
| `daedalus-fab` | [github.com/daedalus-fab](https://linear.app/denman/project/githubcomdaedalus-fab-6d311a6d8d19) | `daedalus-fab/daedalus-fab-mcp-server.rs` | DEN-957 | [PR #5](https://github.com/daedalus-fab/daedalus-fab-mcp-server.rs/pull/5) |
| `athlet-o` | [github.com/athlet-o](https://linear.app/denman/project/githubcomathlet-o-b5a995fed9bb) | `athlet-o/athleto-mcp-server.rs` | DEN-957 | [PR #8](https://github.com/athlet-o/athleto-mcp-server.rs/pull/8) |
| `3FA-app` | [github.com/3FA-app](https://linear.app/denman/project/githubcom3fa-app-c3db52220894) | `3FA-app/3FA-mcp-server.rs` | DEN-957 | [PR #20](https://github.com/3FA-app/3FA-mcp-server.rs/pull/20) |
| `akrion-sim` | [github.com/akrion-sim](https://linear.app/denman/project/githubcomakrion-sim-c66c5e5e8f12) | `akrion-sim/akrion-mcp-server.rs` | DEN-957 | [PR #15](https://github.com/akrion-sim/akrion-mcp-server.rs/pull/15) |
| `discrete-event-systems` | [github.com/discrete-event-systems](https://linear.app/denman/project/githubcomdiscrete-event-systems-4a3086ae0c45) | `discrete-event-systems/des-mcp-server.rs` | DEN-957 | [PR #18](https://github.com/discrete-event-systems/des-mcp-server.rs/pull/18) |
| `scintilla-run` | [github.com/scintilla-run](https://linear.app/denman/project/githubcomscintilla-run-6d9dd5f5e244) | `scintilla-run/scintilla-mcp-server.rs` | DEN-957 | [PR #15](https://github.com/scintilla-run/scintilla-mcp-server.rs/pull/15) |

## DEN-957 test-organization evidence

The Linear issue or project update for each covered organization should link both
the canonical production PR above and the matching test-organization PR below.

| Product project | Test-organization PR | Evidence state |
|---|---:|---|
| `github.com/3FA-app` | [3fa-app-test/mcp-contract-e2e #3](https://github.com/3fa-app-test/mcp-contract-e2e/pull/3) | Exact production Git blobs and executable verifier; no Actions run admitted |
| `fiducia-cloud` | [fiducia-cloud-test/mcp-contract-e2e #2](https://github.com/fiducia-cloud-test/mcp-contract-e2e/pull/2) | Exact production Git blobs and executable verifier; no Actions run admitted |
| `github.com/quaestor-ledger` | [quaestor-ledger-test/mcp-contract-e2e #2](https://github.com/quaestor-ledger-test/mcp-contract-e2e/pull/2) | Exact production Git blobs and executable verifier; no Actions run admitted |
| `github.com/sonus-auris` | [sonus-auris-test/mcp-contract-e2e #2](https://github.com/sonus-auris-test/mcp-contract-e2e/pull/2) | Exact production Git blobs and executable verifier; no Actions run admitted |
| `github.com/scintilla-run` | [scintilla-run-test/mcp-contract-e2e #3](https://github.com/scintilla-run-test/mcp-contract-e2e/pull/3) | Exact production Git blobs and executable verifier; no Actions run admitted |
| `github.com/discrete-event-systems` | [discrete-event-systems-test/.github #6](https://github.com/discrete-event-systems-test/.github/pull/6) | Hosted workflow run `31241357736` passed |

The Benefactor CC, Daedalus Fab, Athlet-O, and Akrion Sim project records should
retain an explicit test-coverage follow-up. No matching installed test repository
was available in this pass, and no substitute organization was invented. The
machine-readable gap record is `den-957-test-org-provenance.json`.

## Required project document

Each project receives a document titled **Rust MCP modularization delivery —
DEN-957**. The document records the immutable shared revision, canonical PR,
reviewed head, merge commit, retained product boundary, validation
qualification, matching test-organization PR when available, and any explicit
coverage gap.

## State policy

- Implementation starts: issue/project item moves to In Progress.
- PR ready: item moves to In Review.
- Runner rejected before checkout or no run admitted: item is Blocked on infrastructure, not failed.
- Exact-source provenance may satisfy an evidence requirement but is not labeled hosted CI.
- Canonical PR merged and evidence recorded: implementation issue moves to Done.
- Test coverage gaps remain follow-up work even when the production modularization is Done.
- A product project remains active unless the product itself is complete; this
  infrastructure wave does not complete the whole product project.
