//! Google Cloud project and enabled-service reads.

use ore_mcp_http::{CredentialHeaders, HardenedHttpClient};
use serde_json::{json, Value};
use url::Url;

use crate::{
    configured_credential, http_failure, project_http, valid_identifier, IntegrationConfigError,
    ProviderId, ProviderRead,
};

const RESOURCE_MANAGER_HOST: &str = "cloudresourcemanager.googleapis.com";
const SERVICE_USAGE_HOST: &str = "serviceusage.googleapis.com";
const SERVICE_LIMIT: usize = 100;

/// Read-only Google Cloud adapter pinned to one project id and number.
#[derive(Clone)]
pub struct GcpAdapter {
    client: HardenedHttpClient,
    project_id: String,
    project_number: String,
}

impl GcpAdapter {
    /// Constructs an adapter for one exact Google Cloud project.
    ///
    /// # Errors
    ///
    /// Project ids must be portable identifiers and project numbers must be
    /// decimal values no longer than 32 digits.
    pub fn new(
        project_id: impl Into<String>,
        project_number: impl Into<String>,
    ) -> Result<Self, IntegrationConfigError> {
        let project_id = project_id.into();
        let project_number = project_number.into();
        if !valid_identifier(&project_id, 63)
            || project_number.is_empty()
            || project_number.len() > 32
            || !project_number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(IntegrationConfigError::InvalidResourceScope);
        }
        Ok(Self {
            client: HardenedHttpClient::default(),
            project_id,
            project_number,
        })
    }

    /// Reads metadata for the configured Google Cloud project.
    pub async fn project(&self, access_token: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_project";
        let Some(access_token) = configured_credential(access_token) else {
            return ProviderRead::not_configured(ProviderId::Gcp, OPERATION);
        };
        let mut endpoint = Url::parse("https://cloudresourcemanager.googleapis.com/v3/projects/")
            .expect("static Google Cloud endpoint");
        endpoint
            .path_segments_mut()
            .expect("hierarchical Google Cloud endpoint")
            .pop_if_empty()
            .push(&self.project_id);
        self.read(
            OPERATION,
            endpoint,
            RESOURCE_MANAGER_HOST,
            access_token,
            project_project,
        )
        .await
    }

    /// Lists a bounded projection of APIs enabled for the configured project.
    pub async fn enabled_services(&self, access_token: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_enabled_services";
        let Some(access_token) = configured_credential(access_token) else {
            return ProviderRead::not_configured(ProviderId::Gcp, OPERATION);
        };
        let mut endpoint = Url::parse("https://serviceusage.googleapis.com/v1/projects/")
            .expect("static Google Cloud endpoint");
        endpoint
            .path_segments_mut()
            .expect("hierarchical Google Cloud endpoint")
            .pop_if_empty()
            .push(&self.project_number)
            .push("services");
        endpoint
            .query_pairs_mut()
            .append_pair("filter", "state:ENABLED")
            .append_pair("pageSize", &SERVICE_LIMIT.to_string());
        self.read(
            OPERATION,
            endpoint,
            SERVICE_USAGE_HOST,
            access_token,
            project_services,
        )
        .await
    }

    async fn read<F>(
        &self,
        operation: &'static str,
        endpoint: Url,
        exact_host: &str,
        access_token: &str,
        project: F,
    ) -> ProviderRead
    where
        F: FnOnce(Value) -> Option<Value>,
    {
        match self
            .client
            .get(
                endpoint.as_str(),
                &[exact_host],
                CredentialHeaders::Bearer(access_token),
                &[("accept", "application/json")],
            )
            .await
        {
            Ok(response) => project_http(ProviderId::Gcp, operation, response, project),
            Err(error) => http_failure(ProviderId::Gcp, operation, error),
        }
    }
}

fn project_project(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    object.get("name")?.as_str()?;
    Some(json!({
        "name": object.get("name"),
        "projectId": object.get("projectId"),
        "displayName": object.get("displayName"),
        "state": object.get("state"),
        "parent": object.get("parent"),
        "createTime": object.get("createTime"),
        "updateTime": object.get("updateTime"),
    }))
}

fn project_services(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    let services = object
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Some(json!({
        "services": services
            .iter()
            .take(SERVICE_LIMIT)
            .filter_map(Value::as_object)
            .map(|service| json!({
                "name": service.get("name"),
                "state": service.get("state"),
                "serviceName": service.get("config").and_then(|config| config.get("name")),
                "title": service.get("config").and_then(|config| config.get("title")),
            }))
            .collect::<Vec<_>>(),
        "truncated": object.get("nextPageToken").is_some() || services.len() > SERVICE_LIMIT,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_scope_requires_id_and_numeric_project_number() {
        assert!(GcpAdapter::new("ore-example", "1234567890").is_ok());
        assert!(GcpAdapter::new("ore/example", "1234567890").is_err());
        assert!(GcpAdapter::new("ore-example", "not-a-number").is_err());
    }

    #[test]
    fn project_projection_omits_labels_and_etags() {
        let projected = project_project(json!({
            "name": "projects/123",
            "projectId": "ore-example",
            "displayName": "Example",
            "state": "ACTIVE",
            "labels": {"credential": "never-return"},
            "etag": "opaque",
        }))
        .expect("valid project");
        assert_eq!(projected["projectId"], "ore-example");
        assert!(projected.get("labels").is_none());
        assert!(projected.get("etag").is_none());
    }
}
