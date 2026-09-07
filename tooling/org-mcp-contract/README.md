# Organization MCP implementation conformance

Tracks DEN-3828 and ORESoftware/typespec-json-schema-validator#20.

This is a reusable Node.js 22 test/admission library, not a new schema compiler,
production authorization middleware, or proof that the whole MCP fleet has passed.
Rust servers remain thin consumers of `ore-mcp-org-server`.

## Two authorities, then a running implementation

`admitContract(validatorApi, checkOptions)` calls the pinned validator's `runCheck`
to compile the authored TypeSpec into a comparison witness, compare that witness
with independently authored Draft 2020-12 JSON Schema, and run differential
fixtures. It builds and verifies Contract IR against the checked-out source
closure. A copied `passed` string, missing evidence, unsupported validation, or
stale inputs cannot substitute for those calls. Neither authored file is rewritten.

The validator API must be imported from a reviewed immutable revision of
`ORESoftware/typespec-json-schema-validator/src/index.mjs`, with its locked
compiler/emitter dependencies installed. It is a trusted dependency, not a
user-supplied plugin. Use a new, empty witness directory for each run.

`checkImplementation({binary, cwd, manifestPath, admitted})` initializes the actual
compiled executable over bounded stdio, checks its advertised schemas, calls every
operation in the explicit manifest with recorded valid and invalid arguments,
and validates output in BOTH native schema lanes. Comparison-normalized IR
references are never executed as runtime schemas. Format-assertion settings are
preserved. Source/IR, binary bytes, and operation-manifest bytes are checked again
before returning passed evidence.

The manifest's schema is `ores.mcp-tool-conformance/v1`; it must name an exact
protocol version and `coverage: "declared-tools-only"`. Each operation declares
`name`, admitted `input`/`output` declaration names, `encoding` (`json_text` or
`structured`), nonempty object-valued `validArguments`/`invalidArguments`, and
scalar `expectedOutput` identity assertions. This is authored operation metadata
and test evidence, not a third data-schema authority. Undeclared tools are NOT
certified. Paginated catalogs are refused rather than incompletely checked.

Legacy `json_text` explicitly supports the template's bounded JSON-string tool
results; it never silently falls back from missing structured output. If a
JSON-text result also has structured content, both must agree. Advertised output
schemas, when present, must agree with the contract. Missing outputSchema on a
legacy tool is not a claim that the server advertises one.

## Safety and evidence

The child receives an empty environment, no shell and no caller credentials.
Stdout/stderr have a shared byte cap; stderr is discarded, responses are matched
to request IDs, and request deadlines terminate stalled children. Diagnostics do
not include server payloads or stderr. Only run reviewed read-only tool manifests;
this runner is not a sandbox for an untrusted executable. It does not exercise
credentialed provider calls, remote HTTP/OAuth, or deployment effects.

The returned result binds `parityRunId`, `contractIrId`, `binarySha256`,
`operationManifestSha256`, tested tool names and positive/negative call counts.
These hashes detect stale artifacts, not malicious forgery; they are not signatures.
The caller must invalidate old output before starting and publish passed evidence
only after the call completes. Attach exact consumer, validator, runner, and
compiler toolchain revisions to the CI evidence; never promote from a saved
status literal alone. Production ingress/egress validators and multi-language
projection generation remain separate issue-20 work.

## Tests

```sh
node --test test/org-mcp-contract.test.mjs
```

The unit suite uses deliberate validator doubles and real stdio exchanges with
small Node subprocess fixtures. Those tests verify runner behavior; they do not
certify TypeSpec compilation or any Rust server. Each consuming template/server
must additionally run the pinned real validator and its compiled Rust binary in
CI. Keep a consumer PR draft until those checks and its own repository gates pass.
