# Rust MCP fleet parity contract v1

Tracking: DEN-161, DEN-779, DEN-852, and DEN-965.

This contract defines what it means for an ORESoftware organization MCP server
to be interoperable, connected, useful, and safe. A profile is evidence about
one exact repository revision. It is not a feature wishlist and it cannot turn
an unimplemented provider into a passing integration by naming it.

The machine-readable authority is [`schema-v1.json`](schema-v1.json). The
validator adds cross-field and source-evidence checks that JSON Schema cannot
express.

## One protocol, several clients

Cursor, ChatGPT/OpenAI, Claude/Anthropic, Gemini, Grok, and Qwen are MCP clients
of the organization server. They are not six provider-specific server
implementations. A conforming server exposes the same MCP tools, resources,
prompts, annotations, schemas, authorization rules, and result semantics to
every client.

Every profile must record evidence for all six clients. Local client evidence
uses stdio. Hosted client evidence uses Streamable HTTP. Legacy SSE may be
retained for a documented compatibility period, but it does not satisfy the
Streamable HTTP requirement.

Current primary references:

- [MCP 2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OpenAI MCP and connectors](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [Cursor MCP transports](https://docs.cursor.com/context/model-context-protocol)
- [Anthropic MCP overview](https://docs.anthropic.com/en/docs/mcp)
- [Gemini CLI MCP configuration](https://google-gemini.github.io/gemini-cli/docs/get-started/configuration.html)
- [Grok MCP servers](https://docs.x.ai/build/features/mcp-servers)
- [Qwen Code MCP](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/)

The final fleet protocol is `2025-11-25` until the protocol policy records a
new final revision and the complete conformance matrix passes. A server must
reject unsupported revisions instead of silently normalizing them.

## Required transports and remote authorization

Every server must support:

1. stdout-pure stdio for local IDE and CLI clients; and
2. Streamable HTTP at a stable HTTPS `/mcp` endpoint for hosted clients.

The remote endpoint is an OAuth 2.1 protected resource. It must publish RFC
9728 Protected Resource Metadata, return an RFC 6750 `WWW-Authenticate`
challenge for unauthorized requests, validate issuer, audience/resource,
authorized client, expiry, not-before, scopes, realm, session, and required
assurance, and use a separate upstream credential for downstream services. An
MCP client token must never be forwarded to GitHub, a cloud provider, a data
platform, Kubernetes, or NATS.

Shared Auth is the fleet authorization authority. Customer and admin realms
remain independent. Product membership and resource authorization remain in
the product authority. Stdio is process-boundary access and cannot be described
as remotely authenticated.

Remote implementations must also enforce exact Host/origin policy, reject URL
userinfo, disable redirects and ambient proxies for credentialed requests,
bound request and response bodies before buffering, apply deadlines, keep
errors secret-free, and expose readiness separately from liveness.

## Required upstream integrations

Every profile must describe real, configurable adapters for these upstreams:

- GitHub;
- AWS;
- GCP;
- Supabase;
- Neon;
- Cloudflare;
- the `ORESoftware/k8s-cluster` deployment plane; and
- NATS.

Each adapter must name its implementation module and symbol, a focused test,
its non-secret configuration-key names, exact allowed origins or endpoint
classes, least-privilege scopes, and at least two org-relevant operations. One
operation must be a real read, not only a configuration or TCP health check.

An adapter reports one of five states:

| State | Meaning |
| --- | --- |
| `ready` | Authentication and the declared read probe succeeded. |
| `not_configured` | Required non-secret routing or secret injection is absent. |
| `degraded` | The authority or dependency could not decide before its deadline. |
| `unauthorized` | The supplied credential is missing, invalid, or expired. |
| `forbidden` | Identity is valid but lacks the required product or provider permission. |

These states are exhaustive and must not be collapsed into an empty success,
`false`, or a generic error. Live provider availability is not required for an
offline test to pass; the implementation and tests must prove that every state
is reachable and semantically distinct.

Supabase and Neon are separate integrations even when they ultimately expose
Postgres. Supabase service-role or secret keys and Neon API keys remain
server-side secrets. Database tools must be scoped, bounded, read-only by
default, and cannot accept arbitrary SQL unless a separate reviewed policy and
runtime authorization gate exists.

Kubernetes access is restricted to the organization's declared namespaces and
resources. NATS access is restricted to declared subject prefixes and account
permissions. Neither adapter may provide arbitrary `kubectl`, shell, wildcard
subject, or generic proxy tools.

## Organization-specific value

Parity is a common quality and integration contract, not an identical generic
tool catalog. Every profile must map the organization's real repositories,
services, runbooks, Kubernetes namespaces, and NATS subjects. It must expose at
least:

- eight organization-specific tools;
- three resources;
- two prompts; and
- one provider-backed read tool that composes information from two or more
  upstream integrations.

Tool descriptions must state the authority, scope, side effects, and meaning of
failure. Input schemas are closed and typed. Results are structured and capped
at a declared byte ceiling. Tools carry correct `readOnlyHint`,
`destructiveHint`, `idempotentHint`, and `openWorldHint` annotations.

The following do not count as organization-specific value:

- identity, version, policy, configuration-presence, or static status alone;
- tools that always return fixtures, empty arrays, `not implemented`, or
  unconditional success;
- arbitrary URL, shell, filesystem, SQL, `kubectl`, cloud-CLI, or NATS proxy
  tools;
- duplicated tools whose only difference is a provider or client brand; or
- capabilities copied from another organization without an owning repository,
  service, namespace, subject, runbook, or product contract.

## Mutations

Read-only is the default. A mutating operation must declare its exact target
class and additionally require:

- independent runtime authorization after MCP authentication;
- an allowlisted organization/project/account/namespace/subject boundary;
- a dry-run or plan result before application;
- target-bound confirmation that expires and cannot authorize a different
  action;
- an idempotency key and replay-safe outcome;
- a bounded audit event without arguments, result bodies, credentials, or user
  data; and
- correct destructive and idempotent MCP annotations.

Prompt approval alone is not an authorization control. An inbound MCP token is
not an upstream provider credential.

## Evidence and completion

A profile is tied to a 40-character Git commit. Its implementation paths,
symbols, and focused tests must exist at that revision. Client and live-provider
evidence must identify a test kind and immutable reference; a mutable branch or
an unqualified statement that a connection works is not evidence.

Completion for one repository requires:

1. JSON Schema validation;
2. the cross-field profile validator;
3. repository-local format, lint, unit, integration, and real-process tests;
4. a matching test-organization conformance run against the exact production
   revision;
5. immutable shared-library pins and a committed lockfile; and
6. a project-scoped Linear issue and GitHub pull request.

Fleet completion additionally requires a generated inventory with no unknown,
missing, duplicate, stale, or unprofiled authoritative server repositories.
Submodule and deployment copies are evidence consumers, never authoritative
implementation repositories.
