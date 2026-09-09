# TJSV runtime-boundary gate

Tracking: DEN-970. Parent architecture: DEN-957 and ORESoftware/typespec-json-schema-validator#20.

## Authority model

TypeSpec and independently authored JSON Schema Draft 2020-12 are peer authorities. The TypeSpec-emitted JSON Schema, Contract IR, generated language bindings, runtime adapters, manifests, and verification receipts are evidence only. A generated artifact never overwrites an authored authority and never wins a disagreement by fallback.

`tooling/org-mcp-contract/tjsv.lock.json` records the reviewed immutable TJSV revision used by this repository. CI checks out that exact 40-character commit, installs its locked npm dependency graph, runs the validator unit suite, and then imports the validator directly from that checkout. Do not replace the pin with `main`, a tag that can move, a branch name, or a caller-supplied module path.

The current reviewed pin is the merged TJSV repair revision `6d560db590cd1a9e03822697f91f6a3f78f6c22a`. Its own `main` push CI is green on Ubuntu and macOS. The previously pinned merge revision `4740f1367a7906813dcd420a77d0c9ede26943fb` is intentionally not acceptable: its upstream push CI was red after a concurrent language-boundary hardening change exposed a stale Lambda test witness. An immutable SHA is necessary, but immutability alone does not make a red upstream commit promotable.

## What the hosted gate proves

`.github/workflows/org-mcp-contract.yml` runs two layers:

1. the dependency-free MCP runner regression suite, including strict JSON/stdio, manifest, exact-catalog, schema-advertisement, invalid-call, timeout, output-bound, and stale-input controls;
2. `test/org-mcp-contract-tjsv.integration.mjs` against the real pinned TJSV compiler and validator stack.

The real-validator layer proves all of the following on every pull request and on `main`/`dev` pushes:

- the checked-out TJSV Git revision exactly equals the committed pin;
- the exact TJSV APIs consumed by `admitContract()` still exist;
- compiler-backed TypeSpec/JSON-Schema parity produces a current parity receipt and admissible Contract IR;
- both independent schema lanes accept representative valid payloads;
- both lanes reject missing required fields, unknown enum values, and undeclared fields;
- compilation leaves both authored authorities byte-for-byte unchanged;
- an intentional TypeSpec/JSON-Schema disagreement fails closed;
- editing an authored schema after admission invalidates retained Contract IR evidence;
- the pinned language-boundary verifier is callable and fails closed without complete runtime evidence;
- the language-boundary result preserves `typeSpecAuthority=peer`, `jsonSchemaAuthority=peer`, and `generatedWitnessRole=evidence_only`.

The integration suite intentionally uses TJSV's reviewed `test/fixtures/pass` authority pair so the consuming runner is tested against the validator's actual compiler/emitter dependency graph rather than a local test double.

## Cross-language promotion

A passing MCP wire test is not enough to certify generated Rust, TypeScript, Dart/Flutter, Gleam, WASM, Qt/QML, Protobuf, WIT, SQL, or ORM projections. Generated language/runtime artifacts must supply native ingress and egress evidence bound to the exact parity `runId`, Contract IR `irId`, immutable source revision, artifact digest, generator, and toolchain, and must pass TJSV language-boundary verification before promotion.

Consumers should use `ORESoftware/typespec-json-schema-validator` language-boundary verification as the promotion decision. Missing, stale, mismatched, or non-passed required evidence is a stopped evaluation, not a warning that can be bypassed.

## Exact tool catalogs and admin/non-admin separation

For promotion of a closed regular MCP binary, use `coverage: "exact-tools"`, `serverClass: "regular"`, and mark every reviewed tool `surface: "regular"`. The runner compares the complete real `tools/list` result to the manifest and fails if the binary exposes any undeclared additional tool. This prevents a regular server from keeping a green receipt while silently gaining an extra privileged/admin command.

`coverage: "declared-tools-only"` remains available only as an explicitly partial migration mode; undeclared tools are not certified in that mode. It must not be relabeled as exact/full coverage.

Privileged `*-admin-mcp-server.rs` services use a separate deployable/repository boundary and may use `serverClass: "admin"` with explicit regular/admin tool surfaces. The classification is review metadata, not authentication. Regular and admin services may share reviewed `*-interfaces`, `*-lib-core`, and `*-orm-core` contracts, but they retain independent binaries, repository permissions, credentials/service identities, OAuth audiences, network/VPC boundaries, approval paths, and authorization policy. Client-supplied `role`, `is_admin`, tenant, or similar fields never establish authority.

Contract parity proves representation and validation behavior; it does not replace shared-auth authorization, tenant/resource checks, replay protection, idempotency, distributed locks/fencing, audit logging, or human approval for privileged commands.

Fleet rollout of exact catalog admission is tracked in `ORESoftware/.github#178`.

## Updating the TJSV pin

A pin update is a reviewed dependency change:

1. choose an immutable TJSV candidate after reviewing its contract/runtime changes;
2. require the **exact commit that consumers will pin** to have its own terminal green upstream CI. A green feature-branch head does not certify a different merge commit;
3. reject missing, zero-step, skipped, cancelled, pending, stale, or failed upstream jobs as pin-health evidence;
4. update `tooling/org-mcp-contract/tjsv.lock.json` and the workflow checkout `ref` together;
5. run the dependency-free runner tests, pinned TJSV unit suite, and the real integration suite on the exact consumer head;
6. keep the pull request unmerged until all applicable exact-head checks are green;
7. after merge, record the merge commit and post-merge evidence on DEN-970 (or its successor rollout issue).

Organization-wide automation for this requirement belongs to `ORESoftware/.github#55`, with compatibility/lock/cohort policy in #75, #77, and #136 rather than another competing validator.

Never place GitHub, Linear, Cloudflare, database, or other credentials in the pin, fixtures, workflow arguments, test diagnostics, or verification receipts.
