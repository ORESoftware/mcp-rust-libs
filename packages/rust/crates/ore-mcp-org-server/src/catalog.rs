//! Organization-specific MCP resources and operator prompts.

use crate::OrgSpec;

/// One immutable resource generated from a validated organization specification.
pub struct ResourceDef {
    /// Exact MCP resource URI.
    pub uri: String,
    /// Human-readable resource name.
    pub name: String,
    /// Resource MIME type.
    pub mime: &'static str,
    /// Bounded resource description.
    pub description: &'static str,
    /// Generated organization-specific Markdown body.
    pub body: String,
}

/// One immutable prompt generated from a validated organization specification.
pub struct PromptDef {
    /// Stable prompt name shared across the fleet.
    pub name: &'static str,
    /// Bounded prompt description.
    pub description: String,
    /// Organization-specific prompt text.
    pub text: String,
}

/// Builds the required organization and cross-fleet contract resources.
#[must_use]
pub fn resources(spec: OrgSpec) -> Vec<ResourceDef> {
    let slug = scope_slug(spec.organization);
    let dependencies = if spec.dependencies.is_empty() {
        "- No Zed dependencies declared".to_owned()
    } else {
        spec.dependencies
            .iter()
            .map(|dependency| format!("- `{dependency}`"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    vec![
        ResourceDef {
            uri: format!("orgmap://{}", spec.organization),
            name: format!("{} organization topology", spec.organization),
            mime: "text/markdown",
            description: "Exact repository, deployment authority, and dependency scopes.",
            body: format!(
                "# {} organization topology\n\n- GitHub organization: `{}`\n- MCP repository: `{}`\n- Service: `{}`\n- Zed package: `{}`\n- Kubernetes authority: `ORESoftware/k8s-cluster`\n- Default namespace: `{slug}`\n- NATS subjects: `{slug}.mcp.service.read.v1` and `{slug}.mcp.dependencies.read.v1`\n\n## Declared dependencies\n\n{dependencies}\n",
                spec.organization,
                spec.organization,
                spec.repository,
                spec.service_name,
                spec.package_name,
            ),
        },
        ResourceDef {
            uri: format!("contract://{}/mcp-clients", spec.organization),
            name: format!("{} MCP client contract", spec.organization),
            mime: "text/markdown",
            description: "Local and remote client compatibility plus Shared Auth boundaries.",
            body: format!(
                "# {} MCP client compatibility\n\nThe same MCP 2025-11-25 catalog supports Cursor, ChatGPT/OpenAI, Claude/Anthropic, Gemini, Grok, and Qwen. Local clients use bounded stdio. Remote clients use OAuth-protected Streamable HTTP at `/mcp`.\n\nRemote Shared Auth tokens are verified locally with exact issuer, audience, authorized client, `{}` project realm, session, scope, role, and AAL2 checks. The caller token is removed before MCP dispatch and is never forwarded to provider APIs.\n",
                spec.organization, spec.organization,
            ),
        },
        ResourceDef {
            uri: format!("contract://{}/providers", spec.organization),
            name: format!("{} provider contract", spec.organization),
            mime: "text/markdown",
            description: "Five-state semantics and exact read-only infrastructure scopes.",
            body: format!(
                "# {} provider contract\n\nEach GitHub, AWS, GCP, Supabase, Neon, Cloudflare, Kubernetes, and NATS check returns exactly one honest state: `ready`, `not_configured`, `degraded`, `unauthorized`, or `forbidden`. Missing configuration is never reported as success.\n\nAll reads are bounded, projected, read-only, and pinned to this server's exact organization, repository, configured cloud resources, Kubernetes namespace, and NATS subjects. Provider credentials are captured from allowlisted process environment keys and are never accepted as tool arguments or returned in results.\n",
                spec.organization,
            ),
        },
        ResourceDef {
            uri: format!("contract://{}/interfaces", spec.organization),
            name: format!("{} interface authority contract", spec.organization),
            mime: "text/markdown",
            description: "Shared and domain interface ownership plus regular/admin reuse rules.",
            body: format!(
                "# {} interface authorities\n\n`ORESoftware/ores-interfaces` is the cross-product shared interface authority. Domain-specific wire models remain owned by the reviewed `*-interfaces` repository for this product family. Regular and admin MCP servers may share those reviewed types, enums, errors, RPC paths and generated clients, but they do not share caller authority, service credentials or authorization policy.\n\nDo not create a second hand-written wire model when an authoritative interface already exists. Generated artifacts must be reproducible and must not become a new source of truth.\n",
                spec.organization,
            ),
        },
        ResourceDef {
            uri: format!("contract://{}/api-docs", spec.organization),
            name: format!("{} API documentation contract", spec.organization),
            mime: "text/markdown",
            description: "ORE API-doc discovery, OpenAPI and MCP operation identity contract.",
            body: format!(
                "# {} API documentation contract\n\nThe API/RPC documentation authority is `ORESoftware/api-docs` using schema `ore.api-docs.v1`. Public services expose canonical discovery at `/.well-known/api-docs` and a canonical OpenAPI 3.1 document at `/openapi.json` where applicable. MCP adapters preserve canonical operation identity and typed request/response contracts instead of inventing undocumented shadow RPCs.\n",
                spec.organization,
            ),
        },
        ResourceDef {
            uri: format!("contract://{}/schema-validation", spec.organization),
            name: format!("{} TypeSpec and JSON Schema admission contract", spec.organization),
            mime: "text/markdown",
            description: "Independent TypeSpec/JSON Schema authorities and fail-closed parity evidence.",
            body: format!(
                "# {} schema admission contract\n\n`ORESoftware/typespec-json-schema-validator` is the parity/admission authority. TypeSpec and authored JSON Schema Draft 2020-12 remain independent top-level authorities; generated evidence is comparison output, not a replacement authority. Missing, stale, mismatched or failed required parity evidence stops promotion. MCP tool schemas, API-doc schemas and generated language interfaces must agree at the reviewed boundary.\n",
                spec.organization,
            ),
        },
        ResourceDef {
            uri: format!("contract://{}/ores-ecosystem", spec.organization),
            name: format!("{} ORE ecosystem integration contract", spec.organization),
            mime: "text/markdown",
            description: "Explicit integration policy for ORESoftware/ores-* repositories.",
            body: format!(
                "# {} ORE ecosystem integration\n\nRepositories matching `ORESoftware/ores-*` are discoverable ecosystem peers. They are not wildcard dependencies: every library, sidecar, interface, middleware, rate-limit, cache, telemetry, RPC, forms, chat or other ORE component used by this server must be declared explicitly and pinned through the repository's dependency/provenance mechanism. Prefer shared components over local reimplementation when their contract matches the product boundary.\n",
                spec.organization,
            ),
        },
    ]
}

/// Builds the required operator prompts.
#[must_use]
pub fn prompts(spec: OrgSpec) -> Vec<PromptDef> {
    vec![
        PromptDef {
            name: "contract_review",
            description: format!(
                "Review {} interface, API-doc and schema authorities for drift.",
                spec.organization
            ),
            text: format!(
                "Review `{}` read-only for contract drift. Read the interface, API-doc, schema-validation and ORE ecosystem resources. Confirm shared types come from `ORESoftware/ores-interfaces` or the product's reviewed `*-interfaces` authority; public RPCs follow `ORESoftware/api-docs`; and TypeSpec plus authored JSON Schema Draft 2020-12 pass `ORESoftware/typespec-json-schema-validator` evidence. Treat stale or missing evidence as a blocker, not a warning.",
                spec.repository,
            ),
        },
        PromptDef {
            name: "dependency_review",
            description: format!(
                "Review the {} server's organization and Zed dependency contract.",
                spec.organization
            ),
            text: format!(
                "Review `{}` without mutation. Read `org_identity`, `zed_dependency_graph`, `security_baseline`, and the organization topology resource. Confirm that every dependency is an immutable organization/repository coordinate, deployment ownership remains in ORESoftware/k8s-cluster, and no provider state is represented as a placeholder success.",
                spec.repository,
            ),
        },
        PromptDef {
            name: "deploy_readiness",
            description: format!(
                "Decide whether the {} MCP and provider stack is ready to deploy.",
                spec.organization
            ),
            text: format!(
                "Assess {} deployment readiness read-only. Call `organization_posture`, treat every `unauthorized`, `forbidden`, or `degraded` provider as a blocker, and treat every `not_configured` provider as an explicit evidence gap. Correlate the exact repository `{}`, ORESoftware/k8s-cluster readiness, NATS dependencies, and declared Zed graph. Report go/no-go, exact blockers, and the responsible boundary. Never request credential values or mutate infrastructure.",
                spec.organization, spec.repository,
            ),
        },
        PromptDef {
            name: "ecosystem_review",
            description: format!(
                "Review {} use of shared ORE ecosystem components.",
                spec.organization
            ),
            text: format!(
                "Review {} read-only for opportunities to reuse explicitly declared `ORESoftware/ores-*` components instead of duplicating middleware, telemetry, interfaces, RPC, caching, rate-limiting, forms, chat or sidecar behavior. Do not infer wildcard dependencies: verify every selected component is declared and pinned, and preserve product-local authorization and data boundaries.",
                spec.organization,
            ),
        },
        PromptDef {
            name: "provider_triage",
            description: format!(
                "Triage a {} infrastructure or dependency failure without mutation.",
                spec.organization
            ),
            text: format!(
                "Triage the {} provider plane read-only. Call `organization_posture`, identify each non-ready provider, then call its dedicated posture tool. Distinguish missing configuration, provider unavailability, invalid authentication, and insufficient authorization. Correlate GitHub CI, Kubernetes workload readiness, and NATS dependency state where available. Do not expose tokens, broaden scopes, or infer that `not_configured` means healthy.",
                spec.organization,
            ),
        },
    ]
}

fn scope_slug(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase() as char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPENDENCIES: &[&str] = &["shared-auth/shared-auth-clients", "zed-pkg/zed-cli"];

    fn spec() -> OrgSpec {
        OrgSpec {
            organization: "example-org",
            repository: "example-org/example-mcp-server.rs",
            service_name: "example-mcp-server",
            package_name: "example-mcp-server",
            dependencies: DEPENDENCIES,
            version: "0.1.0",
        }
    }

    #[test]
    fn catalogs_meet_the_fleet_floor_and_are_org_specific() {
        let resources = resources(spec());
        let prompts = prompts(spec());
        assert_eq!(resources.len(), 7);
        assert_eq!(prompts.len(), 5);
        assert!(resources.iter().all(|resource| {
            resource.uri.contains("example-org") && resource.body.contains("example-org")
        }));
        assert!(prompts
            .iter()
            .all(|prompt| prompt.text.contains("example-org")));
        assert!(resources.iter().all(|resource| !resource.body.is_empty()));
        assert!(prompts.iter().all(|prompt| !prompt.text.is_empty()));
    }
}
