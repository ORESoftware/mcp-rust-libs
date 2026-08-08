# GitHub organization project registry — Rust MCP wave 1

**Updated:** 2026-08-07  
**Tracking issue:** DEN-957

This file is the routing contract for the ten organizations in the first Rust
MCP modularization wave. The canonical Project title is `<organization>-project`.
Where an organization already exposes Project `/1`, that board should receive
the linked pull request and future follow-up issues.

| Organization | Canonical Project title | Project route | Canonical server repository | Wave-1 delivery |
|---|---|---|---|---|
| `benefactor-cc` | `benefactor-cc-project` | `https://github.com/orgs/benefactor-cc/projects/1` | `benefactor-cc/benefactor-cc-mcp-server.rs` | [PR #18](https://github.com/benefactor-cc/benefactor-cc-mcp-server.rs/pull/18) |
| `sonus-auris` | `sonus-auris-project` | `https://github.com/orgs/sonus-auris/projects/1` | `sonus-auris/sonus-auris-mcp-server.rs` | [PR #15](https://github.com/sonus-auris/sonus-auris-mcp-server.rs/pull/15) |
| `fiducia-cloud` | `fiducia-cloud-project` | `https://github.com/orgs/fiducia-cloud/projects/1` | `fiducia-cloud/fiducia-mcp-server.rs` | [PR #16](https://github.com/fiducia-cloud/fiducia-mcp-server.rs/pull/16) |
| `quaestor-ledger` | `quaestor-ledger-project` | `https://github.com/orgs/quaestor-ledger/projects/1` | `quaestor-ledger/quaestor-ledger-mcp-server.rs` | [PR #11](https://github.com/quaestor-ledger/quaestor-ledger-mcp-server.rs/pull/11) |
| `daedalus-fab` | `daedalus-fab-project` | `https://github.com/orgs/daedalus-fab/projects/1` | `daedalus-fab/daedalus-fab-mcp-server.rs` | [PR #5](https://github.com/daedalus-fab/daedalus-fab-mcp-server.rs/pull/5) |
| `athlet-o` | `athlet-o-project` | `https://github.com/orgs/athlet-o/projects/1` | `athlet-o/athleto-mcp-server.rs` | [PR #8](https://github.com/athlet-o/athleto-mcp-server.rs/pull/8) |
| `3FA-app` | `3FA-app-project` | `https://github.com/orgs/3FA-app/projects/1` | `3FA-app/3FA-mcp-server.rs` | [PR #20](https://github.com/3FA-app/3FA-mcp-server.rs/pull/20) |
| `akrion-sim` | `akrion-sim-project` | `https://github.com/orgs/akrion-sim/projects/1` | `akrion-sim/akrion-mcp-server.rs` | [PR #15](https://github.com/akrion-sim/akrion-mcp-server.rs/pull/15) |
| `discrete-event-systems` | `discrete-event-systems-project` | `https://github.com/orgs/discrete-event-systems/projects/1` | `discrete-event-systems/des-mcp-server.rs` | [PR #18](https://github.com/discrete-event-systems/des-mcp-server.rs/pull/18) |
| `scintilla-run` | `scintilla-run-project` | `https://github.com/orgs/scintilla-run/projects/1` | `scintilla-run/scintilla-mcp-server.rs` | [PR #15](https://github.com/scintilla-run/scintilla-mcp-server.rs/pull/15) |

## Test-organization evidence routing

The Project `Evidence` field should link the matching test PR in addition to the
canonical production PR when coverage exists.

| Production organization | Test organization | Test repository or path | Evidence PR | Hosted qualification |
|---|---|---|---:|---|
| `3FA-app` | `3fa-app-test` | `mcp-contract-e2e` | [#3](https://github.com/3fa-app-test/mcp-contract-e2e/pull/3) | Exact-source verifier; no run admitted |
| `fiducia-cloud` | `fiducia-cloud-test` | `mcp-contract-e2e` | [#2](https://github.com/fiducia-cloud-test/mcp-contract-e2e/pull/2) | Exact-source verifier; no run admitted |
| `quaestor-ledger` | `quaestor-ledger-test` | `mcp-contract-e2e` | [#2](https://github.com/quaestor-ledger-test/mcp-contract-e2e/pull/2) | Exact-source verifier; no run admitted |
| `sonus-auris` | `sonus-auris-test` | `mcp-contract-e2e` | [#2](https://github.com/sonus-auris-test/mcp-contract-e2e/pull/2) | Exact-source verifier; no run admitted |
| `scintilla-run` | `scintilla-run-test` | `mcp-contract-e2e` | [#3](https://github.com/scintilla-run-test/mcp-contract-e2e/pull/3) | Exact-source verifier; no run admitted |
| `discrete-event-systems` | `discrete-event-systems-test` | `.github/contract-tests/des-mcp-server` | [#6](https://github.com/discrete-event-systems-test/.github/pull/6) | Hosted run `31241357736` passed |

`benefactor-cc`, `daedalus-fab`, `athlet-o`, and `akrion-sim` had no matching
installed test repository during the 2026-08-07 pass. Their Project items should
record `Risk = runner` or `Risk = dependency` and link the explicit gap in
`den-957-test-org-provenance.md`; no substitute test organization should be
silently used.

## Board fields

Each board should expose at least:

- `Status`: Backlog, Ready, In progress, In review, Blocked, Done;
- `Repository`;
- `Linear issue`;
- `Risk`: none, runner, dependency, security, release;
- `Evidence`: PR, merge commit, workflow run, exact-source verifier, or operator exception.

## Automation contract

1. A Linear issue is the planning authority and carries the acceptance criteria.
2. The GitHub issue or pull request is the implementation authority.
3. Link the Linear issue in the PR body and add the PR to the organization board.
4. Move an item to Done only after the canonical PR merges.
5. A workflow that never receives a runner is `Blocked`, never `Passed`.
6. Exact-source provenance is valid evidence but must not be labeled hosted CI.
7. Superseded PRs are closed and excluded from completion counts.

The current GitHub connector can update repositories, issues, PRs, and merges,
but does not expose GitHub Projects v2 mutations. This registry therefore
documents the canonical board routes and field contract without claiming that
board items were added by this change.
