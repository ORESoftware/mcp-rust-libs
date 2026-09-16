# ORE MCP Fleet Contract v1

Status: proposed fleet standard  
Schema: `ores.mcp-fleet.v1`

This contract standardizes `*-mcp-server.rs` and `*-admin-mcp-server.rs` repositories without erasing product-specific tools.

## Shared authorities

- Interface authority: `ORESoftware/ores-interfaces` for cross-product types; product-owned `*-interfaces` repositories remain authoritative for domain-specific types.
- API/RPC documentation authority: `ORESoftware/api-docs` and the `ore.api-docs.v1` discovery contract.
- Type/schema parity authority: `ORESoftware/typespec-json-schema-validator` using independently authored TypeSpec and JSON Schema Draft 2020-12 evidence.
- Shared MCP runtime: `ORESoftware/mcp-rust-libs`.
- Observability runtime: `ores-otel/ores-mcp-server-core-libs.rs`.
- Ecosystem namespace: repositories matching `ORESoftware/ores-*` are discoverable peers, not implicit dependencies. Every dependency must still be declared explicitly.

## Regular server baseline

Regular organization MCP servers are read-only by default. Tool inputs use closed schemas, outputs are bounded, secrets never enter tool arguments or results, provider reads use exact allowlisted scopes, and missing configuration is never represented as success. Product-specific servers should compose the shared parity handler rather than reimplementing its identity, provider, telemetry, auth-boundary, environment, and security tools.

## Admin server baseline

Administrator MCP servers are separate repositories and deployables with separate binary identity, credentials/service accounts, OAuth audience, network boundary, release approval and authorization policy. A caller-provided `role`, `is_admin`, tenant, project or similar argument never grants administrative authority.

Admin mutation tools must delegate to a reviewed admin API/service boundary. Every mutation has a typed request/response interface, explicit tenant/actor context, reason metadata where appropriate, authorization and step-up checks, idempotency/replay semantics where applicable, and an auditable result. Generic shell execution, arbitrary SQL, unrestricted filesystem access, generic HTTP fetch, plaintext credential access and provider-console impersonation are forbidden.

## Contract admission

A fleet repository is conformant only when all required evidence is current:

1. The repository declares an `ores.mcp-fleet.v1` manifest.
2. Shared and domain interface authorities are explicit; duplicate hand-written wire models are rejected when an authoritative interface exists.
3. Public RPCs are discoverable through `ore.api-docs.v1`; MCP adapters preserve canonical operation identity instead of creating undocumented shadow RPCs.
4. TypeSpec and authored JSON Schema Draft 2020-12 are independently authoritative and pass `ORESoftware/typespec-json-schema-validator` parity checks.
5. Generated artifacts are reproducible, reviewable and not manually edited.
6. Regular/admin tool surfaces are classified separately; classification is metadata and never authentication.
7. Required evidence that is missing, stale, mismatched or failed stops promotion rather than degrading to a warning.

## Recommended MCP resources

Each server should make these contracts discoverable to clients, either directly or through the shared parity layer:

- organization/dependency topology;
- interface authorities and generated-language artifacts;
- API-doc/OpenAPI discovery locations;
- schema/parity evidence and validator revision;
- ORE ecosystem integration map;
- security and regular/admin boundary policy.
