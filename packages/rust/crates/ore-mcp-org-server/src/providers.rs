//! Exact-scope, read-only provider posture shared by organization servers.

use std::time::Duration;

use ore_mcp_integrations::aws::AwsAdapter;
use ore_mcp_integrations::cloudflare::CloudflareAdapter;
use ore_mcp_integrations::gcp::GcpAdapter;
use ore_mcp_integrations::github::GitHubAdapter;
use ore_mcp_integrations::kubernetes::KubernetesAdapter;
use ore_mcp_integrations::nats::NatsAdapter;
use ore_mcp_integrations::neon::NeonAdapter;
use ore_mcp_integrations::supabase::SupabaseAdapter;
use ore_mcp_integrations::{IntegrationState, ProviderId, ProviderRead};
use serde::Serialize;
use serde_json::{json, Value};
use url::Url;

use crate::OrgSpec;

const PROVIDER_RESULT_MAX_BYTES: usize = 128 * 1024;

/// One provider's aggregate five-state result and deliberately projected data.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderReport {
    provider: &'static str,
    state: &'static str,
    scope: Value,
    checks: Vec<ProviderRead>,
}

impl ProviderReport {
    /// Returns the aggregate state used by the composed organization posture.
    #[must_use]
    pub const fn state(&self) -> &'static str {
        self.state
    }
}

#[derive(Clone, Debug, Default)]
struct ProviderConfig {
    github_token: Option<String>,
    aws_account_id: Option<String>,
    aws_eks_clusters: Vec<String>,
    gcp_project_id: Option<String>,
    gcp_project_number: Option<String>,
    gcp_access_token: Option<String>,
    supabase_url: Option<String>,
    supabase_service_role_key: Option<String>,
    neon_organization_id: Option<String>,
    neon_project_id: Option<String>,
    neon_api_key: Option<String>,
    cloudflare_zone: Option<String>,
    cloudflare_zone_id: Option<String>,
    cloudflare_api_token: Option<String>,
    kubernetes_enabled: bool,
    kubernetes_namespace: Option<String>,
    nats_url: Option<String>,
}

impl ProviderConfig {
    fn capture() -> Self {
        Self {
            github_token: first_env(&["ORE_MCP_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]),
            aws_account_id: env_value("ORE_MCP_AWS_ACCOUNT_ID"),
            aws_eks_clusters: env_list("ORE_MCP_AWS_EKS_CLUSTERS"),
            gcp_project_id: env_value("ORE_MCP_GCP_PROJECT_ID"),
            gcp_project_number: env_value("ORE_MCP_GCP_PROJECT_NUMBER"),
            gcp_access_token: env_value("ORE_MCP_GCP_ACCESS_TOKEN"),
            supabase_url: env_value("ORE_MCP_SUPABASE_URL"),
            supabase_service_role_key: env_value("ORE_MCP_SUPABASE_SERVICE_ROLE_KEY"),
            neon_organization_id: env_value("ORE_MCP_NEON_ORGANIZATION_ID"),
            neon_project_id: env_value("ORE_MCP_NEON_PROJECT_ID"),
            neon_api_key: env_value("ORE_MCP_NEON_API_KEY"),
            cloudflare_zone: env_value("ORE_MCP_CLOUDFLARE_ZONE"),
            cloudflare_zone_id: env_value("ORE_MCP_CLOUDFLARE_ZONE_ID"),
            cloudflare_api_token: env_value("ORE_MCP_CLOUDFLARE_API_TOKEN"),
            kubernetes_enabled: env_value("ORE_MCP_K8S_ENABLED").as_deref() == Some("1"),
            kubernetes_namespace: env_value("ORE_MCP_K8S_NAMESPACE"),
            nats_url: env_value("ORE_MCP_NATS_URL"),
        }
    }
}

/// Immutable provider configuration captured once at the process boundary.
#[derive(Clone)]
pub struct ProviderContext {
    spec: OrgSpec,
    config: ProviderConfig,
    scope_slug: String,
    repository_name: &'static str,
}

impl ProviderContext {
    /// Captures the allowlisted provider settings for one validated organization.
    #[must_use]
    pub fn capture(spec: OrgSpec) -> Self {
        Self::with_config(spec, ProviderConfig::capture())
    }

    fn with_config(spec: OrgSpec, config: ProviderConfig) -> Self {
        let repository_name = spec
            .repository
            .split_once('/')
            .map_or(spec.repository, |(_, name)| name);
        Self {
            spec,
            config,
            scope_slug: scope_slug(spec.organization),
            repository_name,
        }
    }

    /// Reads the exact GitHub organization and latest MCP-server workflow run.
    pub async fn github(&self) -> ProviderReport {
        let Ok(adapter) = GitHubAdapter::new(self.spec.organization) else {
            return degraded(
                ProviderId::GitHub,
                "read_github_posture",
                json!({"organization": self.spec.organization, "repository": self.repository_name}),
            );
        };
        let token = self.config.github_token.as_deref();
        let (organization, workflow) = tokio::join!(
            adapter.organization(token),
            adapter.latest_workflow_run(self.repository_name, token)
        );
        report(
            ProviderId::GitHub,
            json!({"organization": self.spec.organization, "repository": self.repository_name}),
            vec![organization, workflow],
        )
    }

    /// Verifies one configured AWS account and a bounded EKS allowlist.
    pub async fn aws(&self) -> ProviderReport {
        let Some(account) = self.config.aws_account_id.as_deref() else {
            return missing(
                ProviderId::Aws,
                "read_aws_posture",
                json!({"accountConfigured": false, "clusters": []}),
            );
        };
        let clusters = self.config.aws_eks_clusters.clone();
        let Ok(adapter) = AwsAdapter::new(account, clusters.clone()) else {
            return degraded(
                ProviderId::Aws,
                "read_aws_posture",
                json!({"accountConfigured": true, "clusters": clusters}),
            );
        };
        let reads = tokio::time::timeout(Duration::from_secs(15), async {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let sts = aws_sdk_sts::Client::new(&config);
            let eks = aws_sdk_eks::Client::new(&config);
            tokio::join!(adapter.caller_identity(&sts), adapter.eks_clusters(&eks))
        })
        .await;
        let Ok((identity, clusters_read)) = reads else {
            return degraded(
                ProviderId::Aws,
                "read_aws_posture",
                json!({"account": account, "clusters": clusters}),
            );
        };
        report(
            ProviderId::Aws,
            json!({"account": account, "clusters": clusters}),
            vec![identity, clusters_read],
        )
    }

    /// Reads one exact Google Cloud project and its enabled APIs.
    pub async fn gcp(&self) -> ProviderReport {
        let (Some(project_id), Some(project_number)) = (
            self.config.gcp_project_id.as_deref(),
            self.config.gcp_project_number.as_deref(),
        ) else {
            return missing(
                ProviderId::Gcp,
                "read_gcp_posture",
                json!({"projectConfigured": false}),
            );
        };
        let Ok(adapter) = GcpAdapter::new(project_id, project_number) else {
            return degraded(
                ProviderId::Gcp,
                "read_gcp_posture",
                json!({"projectConfigured": true}),
            );
        };
        let token = self.config.gcp_access_token.as_deref();
        let (project, services) =
            tokio::join!(adapter.project(token), adapter.enabled_services(token));
        report(
            ProviderId::Gcp,
            json!({"projectId": project_id, "projectNumber": project_number}),
            vec![project, services],
        )
    }

    /// Reads bounded auth settings and Data API shape for one Supabase project.
    pub async fn supabase(&self) -> ProviderReport {
        let Some(base_url) = self.config.supabase_url.as_deref() else {
            return missing(
                ProviderId::Supabase,
                "read_supabase_posture",
                json!({"projectConfigured": false}),
            );
        };
        let Some(host) = Url::parse(base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
        else {
            return degraded(
                ProviderId::Supabase,
                "read_supabase_posture",
                json!({"projectConfigured": true}),
            );
        };
        let Ok(adapter) = SupabaseAdapter::new(base_url, &host) else {
            return degraded(
                ProviderId::Supabase,
                "read_supabase_posture",
                json!({"host": host}),
            );
        };
        let key = self.config.supabase_service_role_key.as_deref();
        let (auth, schema) = tokio::join!(adapter.auth_settings(key), adapter.data_api_schema(key));
        report(
            ProviderId::Supabase,
            json!({"host": host}),
            vec![auth, schema],
        )
    }

    /// Lists organization-filtered Neon projects and optional exact branches.
    pub async fn neon(&self) -> ProviderReport {
        let organization_id = self.config.neon_organization_id.as_deref();
        let Ok(adapter) = NeonAdapter::new(organization_id) else {
            return degraded(
                ProviderId::Neon,
                "read_neon_posture",
                json!({"organizationConfigured": organization_id.is_some()}),
            );
        };
        let key = self.config.neon_api_key.as_deref();
        let mut checks = vec![adapter.projects(Some(&self.scope_slug), key).await];
        if let Some(project_id) = self.config.neon_project_id.as_deref() {
            checks.push(adapter.branches(project_id, key).await);
        }
        report(
            ProviderId::Neon,
            json!({
                "organizationId": organization_id,
                "projectId": self.config.neon_project_id,
                "search": self.scope_slug,
            }),
            checks,
        )
    }

    /// Reads one explicitly configured Cloudflare zone and safe DNS metadata.
    pub async fn cloudflare(&self) -> ProviderReport {
        let Some(zone) = self.config.cloudflare_zone.as_deref() else {
            return missing(
                ProviderId::Cloudflare,
                "read_cloudflare_posture",
                json!({"zoneConfigured": false}),
            );
        };
        let Ok(adapter) = CloudflareAdapter::new([zone]) else {
            return degraded(
                ProviderId::Cloudflare,
                "read_cloudflare_posture",
                json!({"zoneConfigured": true}),
            );
        };
        let token = self.config.cloudflare_api_token.as_deref();
        let mut checks = vec![adapter.zone(zone, token).await];
        if let Some(zone_id) = self.config.cloudflare_zone_id.as_deref() {
            checks.push(adapter.dns_records(zone, zone_id, token).await);
        }
        report(ProviderId::Cloudflare, json!({"zone": zone}), checks)
    }

    /// Inspects deployments and selected pods in one exact organization namespace.
    pub async fn kubernetes(&self) -> ProviderReport {
        let namespace = self
            .config
            .kubernetes_namespace
            .as_deref()
            .unwrap_or(&self.scope_slug);
        let selector = format!("app.kubernetes.io/part-of={}", self.scope_slug);
        let scope = json!({
            "clusterRepository": "ORESoftware/k8s-cluster",
            "namespace": namespace,
            "selector": selector,
        });
        if !self.config.kubernetes_enabled {
            return missing(ProviderId::K8sCluster, "read_k8s_posture", scope);
        }
        let Ok(adapter) = KubernetesAdapter::new([namespace], [&selector]) else {
            return degraded(ProviderId::K8sCluster, "read_k8s_posture", scope);
        };
        let Ok(Ok(client)) =
            tokio::time::timeout(Duration::from_secs(10), kube::Client::try_default()).await
        else {
            return degraded(ProviderId::K8sCluster, "read_k8s_posture", scope);
        };
        let reads = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                adapter.deployments(&client, namespace),
                adapter.pods(&client, namespace, &selector)
            )
        })
        .await;
        let Ok((deployments, pods)) = reads else {
            return degraded(ProviderId::K8sCluster, "read_k8s_posture", scope);
        };
        report(ProviderId::K8sCluster, scope, vec![deployments, pods])
    }

    /// Requests bounded service and dependency snapshots on exact NATS subjects.
    pub async fn nats(&self) -> ProviderReport {
        let service_subject = format!("{}.mcp.service.read.v1", self.scope_slug);
        let dependency_subject = format!("{}.mcp.dependencies.read.v1", self.scope_slug);
        let Ok(adapter) = NatsAdapter::new(
            [&service_subject, &dependency_subject],
            Duration::from_secs(3),
            PROVIDER_RESULT_MAX_BYTES,
        ) else {
            return degraded(
                ProviderId::Nats,
                "read_nats_posture",
                json!({"serviceSubject": service_subject, "dependencySubject": dependency_subject}),
            );
        };
        let scope = json!({
            "serviceSubject": service_subject,
            "dependencySubject": dependency_subject,
        });
        let Some(endpoint) = self.config.nats_url.as_deref() else {
            return missing(ProviderId::Nats, "read_nats_posture", scope);
        };
        let Ok(Ok(client)) =
            tokio::time::timeout(Duration::from_secs(5), async_nats::connect(endpoint)).await
        else {
            return degraded(ProviderId::Nats, "read_nats_posture", scope);
        };
        let (service, dependencies) = tokio::join!(
            adapter.service_snapshot(Some(&client), &service_subject),
            adapter.dependency_snapshot(Some(&client), &dependency_subject)
        );
        report(ProviderId::Nats, scope, vec![service, dependencies])
    }
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn first_env(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env_value(key))
}

fn env_list(key: &str) -> Vec<String> {
    env_value(key)
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn scope_slug(value: &str) -> String {
    let normalized = value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase() as char
            } else {
                '-'
            }
        })
        .collect::<String>();
    normalized.trim_matches('-').to_owned()
}

fn report(provider: ProviderId, scope: Value, checks: Vec<ProviderRead>) -> ProviderReport {
    let state = checks
        .iter()
        .map(ProviderRead::state)
        .max_by_key(|state| state_rank(*state))
        .unwrap_or(IntegrationState::Degraded);
    ProviderReport {
        provider: provider.as_str(),
        state: state.as_str(),
        scope,
        checks,
    }
}

fn missing(provider: ProviderId, operation: &'static str, scope: Value) -> ProviderReport {
    report(
        provider,
        scope,
        vec![ProviderRead::not_configured(provider, operation)],
    )
}

fn degraded(provider: ProviderId, operation: &'static str, scope: Value) -> ProviderReport {
    report(
        provider,
        scope,
        vec![ProviderRead::degraded(provider, operation)],
    )
}

const fn state_rank(state: IntegrationState) -> u8 {
    match state {
        IntegrationState::Ready => 0,
        IntegrationState::NotConfigured => 1,
        IntegrationState::Degraded => 2,
        IntegrationState::Unauthorized => 3,
        IntegrationState::Forbidden => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPENDENCIES: &[&str] = &["shared-auth/shared-auth-clients"];

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
    fn empty_configuration_is_explicitly_not_configured() {
        let context = ProviderContext::with_config(spec(), ProviderConfig::default());
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        for report in runtime.block_on(async {
            vec![
                context.github().await,
                context.aws().await,
                context.gcp().await,
                context.supabase().await,
                context.neon().await,
                context.cloudflare().await,
                context.kubernetes().await,
                context.nats().await,
            ]
        }) {
            assert_eq!(report.state(), "not_configured");
        }
    }

    #[test]
    fn derived_scopes_are_bounded_and_wildcard_free() {
        let context = ProviderContext::with_config(spec(), ProviderConfig::default());
        assert_eq!(context.scope_slug, "example-org");
        for value in [
            context.spec.organization,
            context.repository_name,
            context.scope_slug.as_str(),
        ] {
            assert!(!value.contains('*'));
            assert!(!value.is_empty());
        }
    }
}
