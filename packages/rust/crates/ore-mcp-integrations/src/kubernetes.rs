//! Read-only Kubernetes workload inspection using the official `kube` client.

use k8s_openapi::api::{apps::v1::Deployment, core::v1::Pod};
use kube::{
    api::{Api, ListParams, ResourceExt},
    Client, Error as KubeError,
};
use serde_json::json;

use crate::{valid_identifier, IntegrationConfigError, IntegrationState, ProviderId, ProviderRead};

const OBJECT_LIMIT: u32 = 100;

/// Kubernetes adapter pinned to exact namespaces and label selectors.
#[derive(Clone, Debug)]
pub struct KubernetesAdapter {
    allowed_namespaces: Vec<String>,
    allowed_label_selectors: Vec<String>,
}

impl KubernetesAdapter {
    /// Constructs an adapter with immutable organization workload scopes.
    ///
    /// # Errors
    ///
    /// Empty, duplicate, wildcard, malformed, or oversized scopes are rejected.
    pub fn new(
        allowed_namespaces: impl IntoIterator<Item = impl Into<String>>,
        allowed_label_selectors: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, IntegrationConfigError> {
        let allowed_namespaces = normalized_unique(
            allowed_namespaces.into_iter().map(Into::into).collect(),
            valid_namespace,
        )?;
        let allowed_label_selectors = normalized_unique(
            allowed_label_selectors
                .into_iter()
                .map(Into::into)
                .collect(),
            valid_label_selector,
        )?;
        Ok(Self {
            allowed_namespaces,
            allowed_label_selectors,
        })
    }

    /// Lists a bounded deployment rollup in one allowed namespace.
    pub async fn deployments(&self, client: &Client, namespace: &str) -> ProviderRead {
        const OPERATION: &str = "read_deployments";
        if !self.namespace_allowed(namespace) {
            return ProviderRead::degraded(ProviderId::K8sCluster, OPERATION);
        }
        let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        match api.list(&ListParams::default().limit(OBJECT_LIMIT)).await {
            Ok(list) => ProviderRead::ready(
                ProviderId::K8sCluster,
                OPERATION,
                json!({
                    "namespace": namespace,
                    "deployments": list.items.iter().map(|deployment| {
                        let status = deployment.status.as_ref();
                        json!({
                            "name": deployment.name_any(),
                            "generation": deployment.metadata.generation,
                            "replicas": status.and_then(|value| value.replicas),
                            "readyReplicas": status.and_then(|value| value.ready_replicas),
                            "availableReplicas": status.and_then(|value| value.available_replicas),
                            "updatedReplicas": status.and_then(|value| value.updated_replicas),
                            "unavailableReplicas": status.and_then(|value| value.unavailable_replicas),
                            "observedGeneration": status.and_then(|value| value.observed_generation),
                        })
                    }).collect::<Vec<_>>(),
                    "continue": list.metadata.continue_.is_some(),
                }),
            ),
            Err(error) => kube_failure(OPERATION, &error),
        }
    }

    /// Lists bounded pod readiness for one exact namespace and selector.
    pub async fn pods(
        &self,
        client: &Client,
        namespace: &str,
        label_selector: &str,
    ) -> ProviderRead {
        const OPERATION: &str = "read_pods";
        if !self.namespace_allowed(namespace) || !self.selector_allowed(label_selector) {
            return ProviderRead::degraded(ProviderId::K8sCluster, OPERATION);
        }
        let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
        match api
            .list(
                &ListParams::default()
                    .labels(label_selector)
                    .limit(OBJECT_LIMIT),
            )
            .await
        {
            Ok(list) => ProviderRead::ready(
                ProviderId::K8sCluster,
                OPERATION,
                json!({
                    "namespace": namespace,
                    "labelSelector": label_selector,
                    "pods": list.items.iter().map(|pod| {
                        let status = pod.status.as_ref();
                        let containers = status
                            .and_then(|value| value.container_statuses.as_ref())
                            .map(|statuses| statuses.iter().map(|container| json!({
                                "name": container.name,
                                "ready": container.ready,
                                "restartCount": container.restart_count,
                            })).collect::<Vec<_>>())
                            .unwrap_or_default();
                        json!({
                            "name": pod.name_any(),
                            "phase": status.and_then(|value| value.phase.as_deref()),
                            "reason": status.and_then(|value| value.reason.as_deref()),
                            "podIp": status.and_then(|value| value.pod_ip.as_deref()),
                            "hostIp": status.and_then(|value| value.host_ip.as_deref()),
                            "containers": containers,
                        })
                    }).collect::<Vec<_>>(),
                    "continue": list.metadata.continue_.is_some(),
                }),
            ),
            Err(error) => kube_failure(OPERATION, &error),
        }
    }

    fn namespace_allowed(&self, candidate: &str) -> bool {
        self.allowed_namespaces
            .binary_search_by(|value| value.as_str().cmp(candidate))
            .is_ok()
    }

    fn selector_allowed(&self, candidate: &str) -> bool {
        self.allowed_label_selectors
            .binary_search_by(|value| value.as_str().cmp(candidate))
            .is_ok()
    }
}

fn normalized_unique<F>(
    mut values: Vec<String>,
    validate: F,
) -> Result<Vec<String>, IntegrationConfigError>
where
    F: Fn(&str) -> bool,
{
    if values.is_empty() || values.len() > 100 || values.iter().any(|value| !validate(value)) {
        return Err(IntegrationConfigError::InvalidResourceScope);
    }
    let original_count = values.len();
    values.sort_unstable();
    values.dedup();
    if values.len() != original_count {
        return Err(IntegrationConfigError::InvalidResourceScope);
    }
    Ok(values)
}

fn valid_namespace(value: &str) -> bool {
    valid_identifier(value, 63)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_label_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains('*')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_' | b'.' | b'/' | b',' | b'=' | b'!' | b'(' | b')'
                )
        })
}

fn kube_failure(operation: &'static str, error: &KubeError) -> ProviderRead {
    let (state, diagnostic_code) = match error {
        KubeError::Api(response) if response.code == 401 => {
            (IntegrationState::Unauthorized, "kubernetes_unauthorized")
        }
        KubeError::Api(response) if response.code == 403 => {
            (IntegrationState::Forbidden, "kubernetes_forbidden")
        }
        KubeError::Api(_) => (IntegrationState::Degraded, "kubernetes_api_failure"),
        _ => (IntegrationState::Degraded, "kubernetes_transport_failure"),
    };
    ProviderRead {
        provider: ProviderId::K8sCluster,
        operation,
        state,
        diagnostic_code,
        http_status: match error {
            KubeError::Api(response) => Some(response.code),
            _ => None,
        },
        payload: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_scope_is_exact_and_wildcard_free() {
        let adapter = KubernetesAdapter::new(
            ["threefa", "shared-auth"],
            ["app.kubernetes.io/part-of=threefa"],
        )
        .expect("valid scope");
        assert!(adapter.namespace_allowed("threefa"));
        assert!(!adapter.namespace_allowed("threefa-test"));
        assert!(adapter.selector_allowed("app.kubernetes.io/part-of=threefa"));
        assert!(KubernetesAdapter::new(["*"], ["app=x"]).is_err());
        assert!(KubernetesAdapter::new(["threefa"], ["app=*"]).is_err());
    }
}
