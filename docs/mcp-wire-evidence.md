# Strict MCP wire evidence — DEN-3828 / validator issue 20

`tooling/org-mcp-contract/json.mjs` exports `parseStrictJson` and the versioned
`ores.mcp-strict-json/v1` policy. This is a representation gate for the existing
conformance runner, **not** a schema compiler, JSON Schema authority, production
authorization layer, or proof of full MCP fleet parity.

## Why validate before parsing

Ordinary JSON.parse keeps the last duplicate object member. Decoding a Buffer with
`toString('utf8')` can replace malformed UTF-8 before a schema validator sees it.
A receipt must not certify the resulting lossy interpretation as unambiguous wire
evidence. The new gate checks raw frames, JSON text tool results and operation
manifests before either native schema lane evaluates the parsed instance.

The policy rejects duplicate **decoded** member names at every object depth,
malformed JSON or UTF-8, non-finite number overflow, and lone Unicode surrogates.
It permits at most 64 nested containers and 1 MiB of UTF-8 per parsed document;
callers may lower these bounds, but cannot disable or raise them. The scalar-string
restriction and numeric/depth bounds are this conservative interoperability
profile, not a claim that every implementation applies the same JSON policy.
Ordinary finite JSON numbers retain JavaScript Number semantics; this does not
provide arbitrary-precision decimals or universal cross-language equivalence.

Literal array order and repeated array entries are preserved. Names resembling
schema keywords, `__proto__`, `constructor` and `prototype` remain ordinary own
JSON data. Escaped-equivalent names count as duplicates, but Unicode normalization
forms are not rewritten. Neither authored TypeSpec nor authored JSON Schema is
rewritten. Fresh `runCheck`, `buildContractIr`, `verifyContractIr`, native lane
resolvers and differential payload validation remain the authority checks.

## Transport completion

The shared stdio runner rejects invalid notification envelopes and checks buffered
unterminated stdout on child close. `checkImplementation` drains/closes the child,
checks final transport health, and then re-verifies source/IR, executable bytes and
manifest bytes **before** constructing its passed result. This avoids evaluating
a passed return before cleanup discovers invalid output. It records
`wireJsonPolicy` in addition to the existing binary, manifest and Contract IR IDs.
The existing bounded child shutdown is retained; this tests observed output from
a reviewed executable, not a sandbox or a guarantee about arbitrary future output.

Errors do not echo keys, raw payloads, decoder exceptions, or subprocess stderr.
No inherited credential environment, shell invocation, new provider call, production
runtime behavior, schema authority, or deployment is introduced.

## Verification

```sh
node --test test/org-mcp-*.test.mjs
```

The additional suite includes parser boundary cases and real Node subprocesses:
invalid UTF-8, split multibyte stream chunks, escaped duplicate keys, malformed
notifications, deep frames, overflow numbers, duplicate operation manifests,
ambiguous text payloads, and a final partial frame that must prevent passed
conformance evidence. Its authority double is explicitly a test fixture; actual
compiler/Rust server proof belongs to the consuming template and server CI.

Protocol context: MCP 2025-11-25 specifies UTF-8 newline-delimited JSON-RPC on stdio:
https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
JSON object-name interoperability context: RFC 8259 section 4:
https://www.rfc-editor.org/rfc/rfc8259#section-4

Track rollout and bounded remaining scope in
https://github.com/ORESoftware/typespec-json-schema-validator/issues/20 .
