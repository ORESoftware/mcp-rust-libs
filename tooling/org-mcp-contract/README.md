# Organization MCP implementation conformance

Tracks DEN-970/DEN-3828 and ORESoftware/typespec-json-schema-validator#20.

This is a reusable Node.js 22 test/admission library, not a new schema compiler,
production authorization middleware, or proof that the whole MCP fleet has passed.
Rust servers remain thin consumers of reviewed shared MCP runtime crates.

## Two authorities, then a running implementation

`admitContract(validatorApi, checkOptions)` calls the pinned
`ORESoftware/typespec-json-schema-validator` implementation to compile the authored
TypeSpec into a comparison witness, compare that witness with independently authored
Draft 2020-12 JSON Schema, and run differential fixtures. It builds and verifies
Contract IR against the checked-out source closure. A copied `passed` string,
missing evidence, unsupported validation, or stale inputs cannot substitute for
those calls. Neither authored file is rewritten.

The validator API must be imported from a reviewed immutable revision of
`ORESoftware/typespec-json-schema-validator/src/index.mjs`, with its locked
compiler/emitter dependencies installed. CI must prove that exact upstream revision's
own tests before using it as a consumer gate. It is a trusted dependency, not a
user-supplied plugin. Use a new, empty witness directory for each run.

`checkImplementation({binary, cwd, manifestPath, admitted})` initializes the actual
compiled executable over bounded stdio, checks its advertised schemas, calls every
operation in the explicit manifest with recorded valid and invalid arguments, and
validates output in BOTH native schema lanes. Comparison-normalized IR references
are never executed as runtime schemas. Format-assertion settings are preserved.
Source/IR, binary bytes, and operation-manifest bytes are checked again before
returning passed evidence.

## Catalog coverage and regular/admin separation

The manifest schema is `ores.mcp-tool-conformance/v1` and must name an exact protocol
version. Two coverage modes exist:

- `coverage: "declared-tools-only"` is the legacy partial mode. Every declared tool
  must exist and conform, but undeclared tools are explicitly uncertified.
- `coverage: "exact-tools"` is the promotion mode for a closed deployable catalog.
  It requires `serverClass: "regular"` or `"admin"`, requires every tool to declare
  `surface: "regular"` or `"admin"`, and rejects any additional `tools/list` entry.
  A regular server may declare only regular-surface tools.

Exact catalog equality is deliberately stronger than prefix/name filtering. A
regular server cannot pass merely because all expected tools are present while an
extra administrator tool is also advertised. The reviewed manifest is the complete
surface contract for that binary.

`surface` is review metadata, not authorization. It does not turn an administrator
tool into a safe tool or authenticate a caller. Privileged MCP services still belong
in separate `*-admin-mcp-server.rs` repositories/deployments with separate binary
identity, service account/credentials, OAuth audience, network/VPC boundary, release
approval, and authorization policy. Regular credentials must not gain the admin
backend merely by supplying `role`, `is_admin`, tenant, or another argument.

Each operation also declares admitted `input`/`output` declaration names,
`encoding` (`json_text` or `structured`), nonempty object-valued
`validArguments`/`invalidArguments`, and scalar `expectedOutput` identity assertions.
This is authored operation metadata and test evidence, not a third data-schema
authority. Paginated catalogs are refused rather than incompletely checked.

Legacy `json_text` explicitly supports bounded JSON-string tool results; it never
silently falls back from missing structured output. If a JSON-text result also has
structured content, both must agree. Advertised output schemas, when present, must
agree with the contract. Missing `outputSchema` on a legacy tool is not a claim that
the server advertises one.

## Safety and evidence

The child receives an empty environment, no shell and no caller credentials.
Stdout/stderr have a shared byte cap; stderr is discarded, responses are matched to
request IDs, and request deadlines terminate stalled children. Diagnostics do not
include server payloads or stderr. Only run reviewed read-only tool manifests; this
runner is not a sandbox for an untrusted executable. It does not exercise
credentialed provider calls, remote HTTP/OAuth, or deployment effects.

The returned result binds `parityRunId`, `contractIrId`, `binarySha256`,
`operationManifestSha256`, coverage mode, server class, tested tool names and
positive/negative call counts. These hashes detect stale artifacts, not malicious
forgery; they are not signatures. The caller must invalidate old output before
starting and publish passed evidence only after the call completes. Attach exact
consumer, validator, runner, and compiler toolchain revisions to CI evidence; never
promote from a saved status literal alone.

Production ingress/egress validators and native Rust/TypeScript/Dart/Flutter/Gleam
runtime evidence remain separate promotion requirements. TJSV language-boundary
verification is the fail-closed decision point for those generated runtime artifacts;
missing or stale runtime evidence is not inferred as success.

## Tests

```sh
node --test test/org-mcp-*.test.mjs
```

The dependency-free unit suite uses deliberate validator doubles and real stdio
subprocess fixtures. `test/org-mcp-exact-catalog.test.mjs` specifically proves that
regular exact catalogs reject admin-surface declarations and undeclared advertised
tools while retaining the old partial mode for existing consumers during migration.
Those tests verify runner behavior; they do not certify TypeSpec compilation or any
Rust server.

Each consuming template/server must additionally run the pinned real TJSV revision,
its native language/runtime evidence, and its compiled binary in CI. Keep a consumer
PR unmerged until those exact-head checks and its own repository gates pass.
