# DEN-957 wave-2 Zed publication readiness

**Updated:** 2026-08-08 (America/New_York)  
**Blocking Linear issue:** `DEN-3036`  
**Registry:** `https://registry.zpkg.net`  
**Required package range:** `^0.1.0`  
**Exact Zed CLI revision:** `1ab18fcb2ff884e82af4cac4513d7b983a23c84a`

This ledger coordinates phase C of the four-server wave without duplicating the
completed shared dependency-graph extraction or weakening the consumer lockfile
gates.

## Scope: direct graph versus recursive closure

The four Rust MCP consumers each declare five product packages plus
`shared-auth/shared-auth-clients`. That creates 24 **direct consumer edges** over
21 unique directly referenced package coordinates.

`shared-auth/shared-auth-clients` is not a leaf. Its package manifest depends on
`shared-auth/shared-auth-interfaces` and `shared-auth/shared-auth-lib`, and the
shared-auth library also depends on the interfaces package. The complete graph
therefore contains:

- 4 consumers;
- 21 directly referenced packages;
- 2 transitive-only shared-auth packages;
- 23 packages in the recursive closure;
- 24 consumer-to-package edges;
- 31 package-to-package edges;
- 55 total dependency edges.

| Consumer issue | Consumer repository | Direct packages | Recursive closure |
|---|---|---:|---:|
| `DEN-2285` | `apostille-me/apme-mcp-server.rs` | 6 | 8 |
| `DEN-2287` | `embedded-alerts/eal-mcp-server.rs` | 6 | 8 |
| `DEN-2290` | `evento-globolo/evgl-mcp-server.rs` | 6 | 8 |
| `DEN-2293` | `hacker-house-medellin/hhm-mcp-server.rs` | 6 | 8 |

The machine-readable graph is `fleet/zed-wave-2-packages.json`. It records every
package dependency, validates the graph is acyclic, computes each consumer's
recursive closure, and prevents a misleading direct-only readiness result.

## Current evidence

The initial central probe in
[`ORESoftware/mcp-rust-libs#24`](https://github.com/ORESoftware/mcp-rust-libs/pull/24)
correctly found that none of the 21 directly referenced coordinates had a
compatible public release. Its successful
[run 31268106769](https://github.com/ORESoftware/mcp-rust-libs/actions/runs/31268106769)
is retained as direct-package publication evidence, but is superseded for
resolver readiness by the 23-package recursive model.

The first Apostille Me canary built `zed-pkg/zed-cli` successfully at the exact
revision above using Rust 1.97.1. Its live public-registry preflight then returned
HTTP 404 for all six directly declared coordinates. The durable consumer canary
is merged in
[`apostille-me/apme-mcp-server.rs#4`](https://github.com/apostille-me/apme-mcp-server.rs/pull/4).
It has two distinct gates:

1. a credential-free registry-readiness probe that records absent or
   incompatible direct packages without pretending resolution succeeded;
2. a resolver-generated lock and isolated byte-identical frozen replay that is
   enabled only after its direct graph is published. Zed's resolver remains the
   authority for verifying the transitive closure.

The central workflow
`.github/workflows/zed-wave-2-registry-readiness.yml` probes all 23 coordinates
every day and on relevant changes. Its JSON artifact is recursive publication
evidence only; it never creates or approves a lockfile.

## Package publication backlog

### Apostille Me

- `apostille-me/apme-interfaces`
- `apostille-me/apme-libs`
- `apostille-me/apme-clients`
- `apostille-me/apme-cli`
- `apostille-me/apme-sync`

### Embedded Alerts

- `embedded-alerts/eal-interfaces`
- `embedded-alerts/eal-libs`
- `embedded-alerts/eal-clients`
- `embedded-alerts/eal-cli`
- `embedded-alerts/eal-sync`

### Evento Globolo

- `evento-globolo/evgl-interfaces`
- `evento-globolo/evgl-libs`
- `evento-globolo/evgl-clients`
- `evento-globolo/evgl-cli`
- `evento-globolo/evgl-sync`

### Hacker House Medellín

- `hacker-house-medellin/hhm-interfaces`
- `hacker-house-medellin/hhm-libs`
- `hacker-house-medellin/hhm-clients`
- `hacker-house-medellin/hhm-cli`
- `hacker-house-medellin/hhm-sync`

### Shared-auth recursive subgraph

- `shared-auth/shared-auth-interfaces`
- `shared-auth/shared-auth-lib`
- `shared-auth/shared-auth-clients`

## Dependency order

For each product family:

1. publish `interfaces`;
2. publish `libs` after `interfaces`;
3. publish `clients` after `interfaces` and `libs`;
4. publish `cli` after `interfaces`, `libs`, and `clients`;
5. publish `sync` after `interfaces`.

For shared auth:

1. publish `shared-auth-interfaces`;
2. publish `shared-auth-lib` after interfaces;
3. publish `shared-auth-clients` after interfaces and library.

A coordinate is ready only when the registry returns package metadata containing
a compatible, non-yanked public `0.1.x` release. Repository existence, a Git
tag, a successful pack, or an unpublished local artifact is not enough.

## Source-package release preflight

The first root-package preflight is
[`apostille-me/apme-interfaces#4`](https://github.com/apostille-me/apme-interfaces/pull/4).
Exact Zed validation found and corrected the legacy unsupported
`language = "polyglot"` value to the current `language = "universal"` schema.
The same exact-CLI preflight also established the distinction between source
identity `apostille-me/apme-interfaces` and the repository release target
identity `apostille-me/apme-interfaces-repository`.

No tag or registry write is permitted until the reviewed exact-head preflight is
green. Publication remains behind a protected `zed-registry` environment and a
purpose-specific `ZED_PKG_TOKEN` whose value is never exposed to pull-request
jobs.

## Completion sequence

1. make all 23 source manifests valid under the exact Zed CLI schema;
2. generate and review deterministic release plans and artifacts;
3. create immutable `v0.1.0` tags only on the tested commits;
4. publish every package with artifact hash, size, format, VCS tag, and source
   revision;
5. obtain a central recursive readiness result of `23 / 23`;
6. let the Apostille exact-CLI canary generate the first candidate lock and
   complete an isolated `zed install --frozen --install-mode copy --adapter
   rust` without lock drift;
7. review and commit the resolver-produced lock in a separate exact-head PR;
8. fan the reviewed pattern to Embedded Alerts, Evento Globolo, and Hacker
   House Medellín;
9. retain clean-clone frozen-install CI in all four consumers.

No hand-written lock, placeholder digest, floating source reference, green
readiness probe, or successfully packed but unpublished artifact may be
represented as resolver/frozen-install success.

## Agent coordination

Phase A, the shared version-neutral dependency-graph contract, is complete in
`ore-mcp-zed-graph`. Phase B, official `rmcp` runtime and real-process protocol
conformance, remains a separate lane. Phase C publication and lock generation
is coordinated through
[`ORESoftware/mcp-rust-libs#25`](https://github.com/ORESoftware/mcp-rust-libs/issues/25)
and Linear `DEN-3036`; agents should claim a package family before opening
publication PRs.

The AI Agent Bridge exact-image Kubernetes smoke was re-run successfully on
[`ORESoftware/k8s-cluster` run 31242332501, attempt 2](https://github.com/ORESoftware/k8s-cluster/actions/runs/31242332501).
That execution covered authenticated HTTP, SSE, TCP, single, sequential,
competitive, and consensus workflows plus fenced lease lifecycle. Direct bridge
DNS was unavailable from the local task runtime, so the reviewed Kubernetes
workflow was used instead of exposing the bridge bearer credential.

## Security qualification

The readiness workflows use read-only repository permissions, full action
commit pins, and `persist-credentials: false`. They use no GitHub PAT, Linear
token, Cloudflare token, R2 key, or private registry credential. Uploaded JSON
and candidate-lock artifacts are scanned for credential-shaped values.
