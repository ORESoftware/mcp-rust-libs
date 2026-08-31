# mcp-rust-libs

Canonical shared hardening and conformance infrastructure for ORESoftware's Rust MCP server fleet.

## Fleet audit

The historical August 2, 2026 connected-fleet audit found 24 existing standalone Rust MCP repositories and five verified missing servers. The current August 31 parity audit discovers 53 local candidate checkouts, resolves them to 51 authoritative GitHub repositories across 48 production organizations and one sibling test organization, records two duplicate checkouts, and leaves no checkout unclassified. All 51 authoritative repositories currently have at least one high finding, beginning with the absent exact-revision parity profile; this is the migration baseline, not a compliance claim. See the [machine-readable report](fleet/audit-2026-08-31-provider-parity.json) and [review matrix](fleet/audit-2026-08-31-provider-parity.md).

The highest-value recurring defects are:

- hand-written JSON-RPC transports pinned to old MCP revisions;
- bearer-authenticated HTTP clients without exact host or redirect policy;
- successful and error response bodies buffered without a pre-buffer byte cap;
- child processes captured through `wait_with_output`, allowing unbounded stdout/stderr memory use;
- stdout log pollution and marker-based rather than semantic JSON-RPC tests;
- copied startup flag discovery, telemetry attribute filtering, transport identity, and server bootstrap code drifting independently across repositories.

Regenerate the current report from a workspace root with:

```sh
python3 tooling/audit_mcp_fleet.py \
  --workspace-root /path/to/codes \
  --json-report fleet/audit-current.json \
  --markdown-report fleet/audit-current.md
```

Discovery excludes `dd/`, monorepo `apps/`, Kubernetes deployment copies,
repository seeds, dependencies, and build output. GitHub origins are
canonicalized and deduplicated before the per-repository auditor runs.

## Shared Rust crates

The `packages/rust` workspace contains narrow, version-neutral infrastructure:

- `ore-mcp-bootstrap` — strict startup-config discovery, secret-free option redaction, bounded telemetry resource-attribute policy, and validated server/transport identity;
- `ore-mcp-config` — strict flags2env audit/parsing/coercion with unknown/positional rejection, deterministic source precedence, environment-only secret policy, and value-free diagnostics;
- `ore-mcp-safety` — UTF-8-safe truncation, bounded incremental bytes, error redaction, and header validation;
- `ore-mcp-http` — exact URL parsing, loopback-only HTTP, bearer-host allowlists, and a concrete credential-safe read client with redirects and ambient proxies disabled, bounded deadlines, sensitive headers, status-state classification, and incremental response-body bounds;
- `ore-mcp-integrations` — closed, read-first adapters for GitHub, AWS STS/EKS, GCP, Supabase, Neon, Cloudflare, Kubernetes, and NATS, with exact organization scopes, bounded projections, and the shared five-state outcome model;
- `ore-mcp-org-server` — a complete read-only organization server with 15 closed tools, three generated resources, three operator prompts, exact MCP 2025-11-25 stdio, OAuth-protected Streamable HTTP, `ores-otel`, the Zed graph, and all eight fleet providers;
- `ore-mcp-process` — fail-fast or truncating concurrent stdout/stderr capture with timeout, kill, and reap behavior;
- `ore-mcp-remote` — exact MCP 2025-11-25 Streamable HTTP at `/mcp`, RFC 9728 discovery, exact Host/Origin checks, bounded bodies and stateful identity bindings, and local Shared Auth ES256 verification across issuer, audience, OAuth client, realm, session, scope, role, and assurance boundaries;
- `ore-mcp-runtime` — official `rmcp` stdio lifecycle plus exact final-protocol enforcement before SDK negotiation;
- `ore-mcp-telemetry` — stderr-only JSON logging, bounded secret-safe resource assembly, validated optional OTLP endpoints, fail-open OpenTelemetry 0.32 trace/metric exporters, and bounded-cardinality tool labels that never record arguments or results;
- `ore-mcp-testkit` — semantic JSON-RPC 2.0 stdio, initialize, catalog, result, byte/frame-limit, and stdout-purity audits;
- `ore-mcp-zed-graph` — bounded package-coordinate validation plus the shared closed-world dependency-graph descriptor and result contract.

The bootstrap and config layers intentionally avoid a hidden fleet-wide `rmcp` or OpenTelemetry upgrade. `ore-mcp-http` now enables its concrete `reqwest-client` feature by default so provider adapters share one reviewed credentialed-read boundary; consumers that need policy types only can disable default features. `ore-mcp-integrations` fixes provider endpoints and operations while requiring each consumer to supply exact organization resources, credentials, product authorization, MCP tool composition, and final output bounds. Its AWS, Kubernetes, and NATS implementations are opt-in so servers do not acquire unrelated SDKs. `ore-mcp-remote` applies one authenticated remote transport to the same product service used by stdio; it never forwards the caller's Shared Auth token to a provider, and its bounded JWKS fetcher disables redirects and ambient proxies. `ore-mcp-telemetry` keeps endpoint validation, resource assembly, stderr logging, and tool-span helpers available with `--no-default-features`; the optional `otlp` feature constructs OpenTelemetry 0.32 exporters for the current signed cohort. The separately named `ore-mcp-org-server` is the opinionated organization baseline: it pins `ores-otel/ores-mcp-server-core-libs.rs` at a reviewed immutable revision, generates organization-specific resources and prompts from `OrgSpec`, and composes the eight real provider adapters behind one closed, read-only catalog.

Product tools, authorization, mutation gates, credentials, OTLP authentication headers, upstream business clients, concrete exporters, client timeouts, package coordinates, `rmcp`-version-specific tool wrapping, and domain policy remain in their owning repositories.

## Client and provider parity

[`contracts/mcp-fleet-parity/contract-v1.md`](contracts/mcp-fleet-parity/contract-v1.md)
defines the evidence required before a server can claim client interoperability,
upstream connectivity, or organization-specific value. The v1 profile requires
the same final MCP surface for Cursor, ChatGPT/OpenAI, Claude/Anthropic, Gemini,
Grok, and Qwen; stdout-pure stdio plus OAuth-protected Streamable HTTP; and real
read-first adapters for GitHub, AWS, GCP, Supabase, Neon, Cloudflare, the
ORESoftware Kubernetes cluster, and NATS.

The dependency-free validator checks cross-field semantics and exact repository
evidence in addition to the checked-in JSON Schema. It rejects duplicate clients
or providers, missing read operations, absent implementation symbols or tests,
no-op markers, unscoped origins, credential-shaped values, incomplete provider
failure states, weak remote authorization claims, generic tool catalogs, and
mutable evidence references.

```sh
python3 tooling/validate_mcp_fleet_profile.py \
  --profile /path/to/mcp-fleet-profile.json \
  --repo-root /path/to/exact/server/checkout
```

Tracking: DEN-965.

`ore-mcp-org-server::run_stdio` exposes the final protocol locally.
`ore-mcp-org-server::run_http` exposes the same catalog remotely and requires
`ORE_MCP_PUBLIC_RESOURCE`, `SHARED_AUTH_ISSUER`, and `SHARED_AUTH_JWKS_URL`;
authorized client IDs, exact origins, and the loopback-default bind may be set
with `ORE_MCP_OAUTH_CLIENT_IDS`, `ORE_MCP_ALLOWED_ORIGINS`, and
`ORE_MCP_HTTP_BIND`. The default authorized client families are Cursor,
OpenAI/ChatGPT, Anthropic/Claude, Gemini, Grok, and Qwen.

Provider credentials and exact scopes are process-environment settings, never
tool arguments: `ORE_MCP_GITHUB_TOKEN`; `ORE_MCP_AWS_ACCOUNT_ID` plus
`ORE_MCP_AWS_EKS_CLUSTERS`; `ORE_MCP_GCP_PROJECT_ID`,
`ORE_MCP_GCP_PROJECT_NUMBER`, and `ORE_MCP_GCP_ACCESS_TOKEN`;
`ORE_MCP_SUPABASE_URL` plus `ORE_MCP_SUPABASE_SERVICE_ROLE_KEY`;
`ORE_MCP_NEON_ORGANIZATION_ID`, `ORE_MCP_NEON_PROJECT_ID`, and
`ORE_MCP_NEON_API_KEY`; `ORE_MCP_CLOUDFLARE_ZONE`,
`ORE_MCP_CLOUDFLARE_ZONE_ID`, and `ORE_MCP_CLOUDFLARE_API_TOKEN`;
`ORE_MCP_K8S_ENABLED=1` plus an optional exact `ORE_MCP_K8S_NAMESPACE`; and
`ORE_MCP_NATS_URL`. Missing configuration returns `not_configured`; it never
becomes a synthetic success.

## API documentation and MCP discovery

[`contracts/api-docs/contract-v1.md`](contracts/api-docs/contract-v1.md) defines the
framework-neutral `ore.api-docs.v1` contract for every fleet API server and its
organization-level `*-mcp-server.rs` counterpart. The standard fixes the public
discovery, OpenAPI, compatibility-alias, and browser-UI routes; separates
authenticated internal docs; and requires five read-only MCP documentation
tools without granting arbitrary API execution.

The standard-library-only validator proves exact OpenAPI response-byte SHA-256
parity, OpenAPI 3.1 metadata, stable unique operation IDs, public/internal
separation, same-organization API/MCP pairing, and fail-closed mutation
classification. The checked-in schema and fixtures let Rust, Node, Dart, Gleam,
and mixed-language repositories consume the same gate.

```sh
python3 tooling/validate_api_docs_contract.py \
  --manifest contracts/api-docs/example.manifest.json \
  --openapi contracts/api-docs/example.openapi.json \
  --expected-mcp-repository example/example-mcp-server.rs \
  --operations

python3 -m unittest -v tooling/test_validate_api_docs_contract.py
```

Tracking: DEN-3158.

## First ten-server migration wave

The initial consumer wave is:

1. `benefactor-cc/benefactor-cc-mcp-server.rs`
2. `sonus-auris/sonus-auris-mcp-server.rs`
3. `fiducia-cloud/fiducia-mcp-server.rs`
4. `quaestor-ledger/quaestor-ledger-mcp-server.rs`
5. `daedalus-fab/daedalus-fab-mcp-server.rs`
6. `athlet-o/athleto-mcp-server.rs`
7. `3FA-app/3FA-mcp-server.rs`
8. `akrion-sim/akrion-mcp-server.rs`
9. `discrete-event-systems/des-mcp-server.rs`
10. `scintilla-run/scintilla-mcp-server.rs`

`usa-acc/usa-acc-mcp-server.rs` was removed from this bootstrap wave after source inspection showed that its `src/telemetry.rs` is a product Supabase telemetry client rather than the repeated process-OpenTelemetry bootstrap. It remains eligible for a later HTTP/body-policy migration.

See [`fleet/modularization-wave-1.md`](fleet/modularization-wave-1.md) for ownership boundaries, dependency order, and per-repository validation requirements.

## Zed dependency-graph migration wave

A dated second wave covers four short-name servers published after the August 2 inventory:

1. `apostille-me/apme-mcp-server.rs`
2. `embedded-alerts/eal-mcp-server.rs`
3. `evento-globolo/evgl-mcp-server.rs`
4. `hacker-house-medellin/hhm-mcp-server.rs`

All four now use exact official `rmcp 2.2.0`, the shared runtime and graph contract, and final MCP `2025-11-25`. Each passed locked hardened CI plus Rust 1.88.0 and 1.97.1 real-process conformance, including generic rejection of preview `2026-07-28` and legacy `2025-06-18` before SDK normalization.

Independent matching test-organization matrices also execute the exact Embedded Alerts and Evento Globolo production merges on Linux, macOS, and Windows. Dedicated test repositories for all four matching organizations remain tracked separately.

Zed package provenance is not complete: the recursive publication monitor currently reports zero of 23 packages ready, so resolver-generated `.zpkg.lock` and isolated `zed install --frozen` evidence remain blocked on publication rather than runtime correctness.

See [`fleet/modularization-wave-2-zed-graph.md`](fleet/modularization-wave-2-zed-graph.md), its [machine-readable record](fleet/modularization-wave-2-zed-graph.json), and the [test-organization provenance ledger](fleet/modularization-wave-2-runtime-test-org-provenance.md). The historical August 2 inventory remains unchanged.

## Protocol policy

Production follows final MCP `2025-11-25`. Preview `2026-07-28` remains disabled until upstream finalization and explicit conformance. New migrations use official SDK dispatch and an exact protocol boundary rather than hand-written transports or negotiated-version normalization.

## Validation

```sh
cd packages/rust
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo doc --locked --workspace --no-deps

python3 -m unittest -v \
  tooling/test_audit_mcp_fleet.py \
  tooling/test_audit_rust_mcp_server.py \
  tooling/test_check_deployable_lockfile.py \
  tooling/test_check_fleet_pr_evidence.py \
  tooling/test_check_wave2_evidence.py \
  tooling/test_validate_mcp_fleet_profile.py \
  tooling/test_validate_api_docs_contract.py
python3 tooling/audit_rust_mcp_server.py --repo-root /path/to/mcp-server
python3 tooling/audit_mcp_fleet.py --workspace-root /path/to/codes
python3 tooling/check_wave2_evidence.py
```

Tracking: DEN-957, DEN-959, DEN-960, DEN-965, DEN-779, DEN-852, DEN-161, DEN-3081, DEN-3100, and DEN-3158.
