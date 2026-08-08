# DEN-957 wave-2 Zed publication readiness

**Updated:** 2026-08-08 (America/New_York)  
**Registry:** `https://registry.zpkg.net`  
**Required consumer range:** `^0.1.0`  
**Exact Zed CLI revision:** `1ab18fcb2ff884e82af4cac4513d7b983a23c84a`

This ledger coordinates phase C of the four-server wave without duplicating the
completed shared dependency-graph extraction or weakening the consumer lockfile
gates.

## Scope

Four Rust MCP consumers declare five product packages plus the shared auth
client. That produces 24 dependency edges over 21 unique Zed package
coordinates:

| Consumer issue | Consumer repository | Product packages | Shared package |
|---|---|---:|---:|
| `DEN-2285` | `apostille-me/apme-mcp-server.rs` | 5 | 1 |
| `DEN-2287` | `embedded-alerts/eal-mcp-server.rs` | 5 | 1 |
| `DEN-2290` | `evento-globolo/evgl-mcp-server.rs` | 5 | 1 |
| `DEN-2293` | `hacker-house-medellin/hhm-mcp-server.rs` | 5 | 1 |

Every expected source repository exists. Twenty are public product repositories;
`shared-auth/shared-auth-clients` is a private source repository whose package
coordinate is nevertheless required by every consumer.

The machine-readable graph is `fleet/zed-wave-2-packages.json`.

## Current evidence

The first Apostille Me canary built `zed-pkg/zed-cli` successfully at the exact
revision above using Rust 1.97.1. Its live public-registry preflight then returned
HTTP 404 for all six declared coordinates. The result proves that the immediate
blocker is package publication rather than Zed CLI compilation or a fabricated
consumer lock.

The durable Apostille canary is maintained in
[`apostille-me/apme-mcp-server.rs#4`](https://github.com/apostille-me/apme-mcp-server.rs/pull/4).
It now has two distinct gates:

1. a credential-free registry-readiness probe that records absent or
   incompatible packages without pretending resolution succeeded;
2. a resolver-generated lock and isolated byte-identical frozen replay that is
   automatically enabled only when all six exact coordinates have a compatible
   public `0.1.x` release.

The central workflow
`.github/workflows/zed-wave-2-registry-readiness.yml` applies the same readiness
qualification to all 21 coordinates every day and on relevant changes. Its JSON
artifact is publication evidence only; it never creates or approves a lockfile.

## Package publication backlog

### Apostille Me

- `apostille-me/apme-cli`
- `apostille-me/apme-clients`
- `apostille-me/apme-interfaces`
- `apostille-me/apme-libs`
- `apostille-me/apme-sync`

### Embedded Alerts

- `embedded-alerts/eal-cli`
- `embedded-alerts/eal-clients`
- `embedded-alerts/eal-interfaces`
- `embedded-alerts/eal-libs`
- `embedded-alerts/eal-sync`

### Evento Globolo

- `evento-globolo/evgl-cli`
- `evento-globolo/evgl-clients`
- `evento-globolo/evgl-interfaces`
- `evento-globolo/evgl-libs`
- `evento-globolo/evgl-sync`

### Hacker House Medellín

- `hacker-house-medellin/hhm-cli`
- `hacker-house-medellin/hhm-clients`
- `hacker-house-medellin/hhm-interfaces`
- `hacker-house-medellin/hhm-libs`
- `hacker-house-medellin/hhm-sync`

### Shared dependency

- `shared-auth/shared-auth-clients`

## Completion sequence

A coordinate is ready only when the public registry returns package metadata
containing a compatible, non-yanked `0.1.x` version. Repository existence, a Git
tag, or an unpublished local artifact is not enough.

The phase-C sequence is:

1. publish every source package with artifact hash, size, archive format, VCS
   tag, and source revision;
2. obtain a central readiness result of `21 / 21`;
3. let the Apostille exact-CLI canary generate the first candidate lock and
   complete an isolated `zed install --frozen --install-mode copy --adapter
   rust` without lock drift;
4. review and commit the resolver-produced lock in a separate exact-head PR;
5. fan the reviewed pattern to Embedded Alerts, Evento Globolo, and Hacker
   House Medellín;
6. retain clean-clone frozen-install CI in all four consumers.

No hand-written lock, placeholder digest, floating source reference, or
successful readiness probe may be represented as resolver/frozen-install
success.

## Agent coordination

Phase A, the shared version-neutral dependency-graph contract, is complete in
`ore-mcp-zed-graph`. Phase B, official `rmcp` runtime and real-process protocol
conformance, remains a separate lane. Phase C publication and lock generation
is coordinated through `ORESoftware/mcp-rust-libs#15`; agents should claim a
package family there before opening publication PRs.

The AI Agent Bridge exact-image Kubernetes smoke was re-run successfully on
[`ORESoftware/k8s-cluster` run 31242332501, attempt 2](https://github.com/ORESoftware/k8s-cluster/actions/runs/31242332501).
That execution covered authenticated HTTP, SSE, TCP, single, sequential,
competitive, and consensus workflows plus fenced lease lifecycle. Direct bridge
DNS was unavailable from the local task runtime, so the reviewed Kubernetes
workflow was used instead of exposing the bridge bearer credential.

## Security qualification

Both readiness workflows use read-only repository permissions, full action
commit pins, and `persist-credentials: false`. They use no GitHub PAT, Linear
token, Cloudflare token, R2 key, or private registry credential. Uploaded JSON
and candidate-lock artifacts are scanned for credential-shaped values.
