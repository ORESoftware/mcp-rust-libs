# API documentation and MCP discovery contract v1

Status: proposed fleet standard  
Schema: `ore.api-docs.v1`

This contract gives every HTTP API and its organization-level Rust MCP server one
stable, machine-readable documentation surface. It is framework-neutral:
Axum/Utoipa, Node, Gleam, Dart, and other servers may generate the document
differently, but the externally observable routes and metadata are identical.

## Required HTTP routes

Every public API server exposes these unauthenticated `GET` routes:

| Route | Purpose |
|---|---|
| `/.well-known/api-docs` | Discovery manifest conforming to `manifest.schema.json` |
| `/openapi.json` | Canonical public OpenAPI 3.1 document |
| `/api/docs.json` | Byte-for-byte compatibility alias of `/openapi.json` |
| `/api/docs` | Canonical browser documentation UI |
| `/docs/api` | Compatibility alias or permanent redirect to `/api/docs` |

Servers with non-public operations additionally expose authenticated routes:

| Route | Purpose |
|---|---|
| `/internal/openapi.json` | Internal-only OpenAPI 3.1 document |
| `/internal/docs/api` | Internal-only browser documentation UI |

`HEAD` must behave like `GET` without a response body. Documentation routes do
not inherit application authentication accidentally: public routes are
explicitly anonymous, while internal routes use the same organization identity
boundary as the protected API.

## Response requirements

The exact bytes returned by `/openapi.json` and `/api/docs.json` are identical.
Their SHA-256 digest equals `public.openapi.sha256` in the discovery manifest.

Preferred content types:

- discovery manifest: `application/json`;
- OpenAPI: `application/vnd.oai.openapi+json;version=3.1`;
- UI: `text/html; charset=utf-8`.

Public JSON responses should include an `ETag`, `X-OpenAPI-SHA256`, and
`X-Content-Type-Options: nosniff`. Production may cache public documents for a
short period; internal documents use `Cache-Control: no-store`.

The public manifest contains only root-relative paths. Absolute URLs,
scheme-relative URLs, credentials, query strings, fragments, redirects to a
different origin, and cross-origin document references are forbidden.

## OpenAPI rules

The canonical public document uses OpenAPI 3.1.x. Every HTTP operation has:

- a unique, stable `operationId`;
- a non-empty `summary` and at least one tag;
- `x-ore-visibility`: `public` or `internal`;
- `x-ore-stability`: `stable`, `beta`, or `experimental`;
- `x-ore-mcp-expose`: whether the read-only MCP catalog may expose the
  operation description;
- `x-ore-mcp-mutating`: whether invoking the operation could mutate state.

A public document cannot contain internal paths or operations. `GET`, `HEAD`,
and `OPTIONS` operations are non-mutating. `POST`, `PUT`, `PATCH`, `DELETE`, and
`TRACE` are treated as mutating for the baseline contract. Mutating operations
cannot be exposed as executable MCP tools by this baseline.

Rust Axum services should prefer code-first generation with Utoipa
(`OpenApiRouter`/`utoipa_axum::routes!`) and a CI parity test that compares the
live router method/path set with the generated document. Other stacks must
provide an equivalent deterministic route-to-spec parity gate.

## Organization-level MCP integration

Each GitHub organization that owns an API server also owns a standalone
`*-mcp-server.rs` repository. The discovery manifest names that repository
explicitly, and both repositories belong to the same organization.

The baseline MCP integration is read-only and provides these tools:

| Tool | Behavior |
|---|---|
| `api_docs_discover` | Return the validated discovery manifest and provenance |
| `api_docs_get_openapi` | Return the bounded public OpenAPI document |
| `api_docs_validate` | Report schema, digest, operation, and pairing checks |
| `api_docs_list_operations` | List/filter normalized operations |
| `api_docs_describe_operation` | Describe one operation by `operationId` |

Recommended MCP resources are `api-docs://manifest`,
`api-docs://openapi/public`, and
`api-docs://operation/{operationId}`.

This contract does **not** authorize arbitrary HTTP execution. Any future API
invocation tool is a separate capability with an explicit operation allowlist,
credential boundary, mutation classification, idempotency policy, audit
record, and confirmation gate.

## MCP network safety

A live-document MCP client:

- accepts HTTPS and loopback HTTP only;
- starts from a configured API base URL;
- fetches `/.well-known/api-docs` first;
- resolves only root-relative, same-origin document paths;
- disables redirects;
- limits the manifest to 256 KiB and OpenAPI to 8 MiB before buffering;
- sends no credential for public docs;
- uses an exact-host allowlist and separate credential for internal docs;
- redacts URLs, headers, and bodies from errors and telemetry.

A build-pinned snapshot is acceptable when production networking is
intentionally unavailable, provided CI proves byte parity with the API server
and records the API commit SHA.

## Required CI gates

Before promotion from a matching `*-test` organization:

1. validate the discovery manifest and exact OpenAPI bytes;
2. prove `/openapi.json` and `/api/docs.json` byte parity;
3. verify the manifest SHA-256;
4. verify OpenAPI 3.1, unique operation IDs, route coverage, visibility, and
   mutation metadata;
5. prove protected operations are absent from the public document;
6. prove the paired `*-mcp-server.rs` exposes the five read-only tools;
7. prove MCP parsing rejects malformed, oversized, cross-origin, duplicate,
   internal-leaking, and mutation-confused fixtures;
8. run exact-head API + MCP integration in the matching test organization.

Production repositories merge only after the exact source SHAs pass those
gates. Generated SDKs consume `/openapi.json`; generated clients and MCP
snapshots record the same SHA-256 provenance.

## Validation

From this repository:

```sh
python3 tooling/validate_api_docs_contract.py \
  --manifest contracts/api-docs/example.manifest.json \
  --openapi contracts/api-docs/example.openapi.json \
  --expected-mcp-repository example/example-mcp-server.rs \
  --operations

python3 -m unittest -v tooling/test_validate_api_docs_contract.py
```
