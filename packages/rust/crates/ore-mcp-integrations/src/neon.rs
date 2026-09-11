//! Neon project and branch reads.

use ore_mcp_http::{CredentialHeaders, HardenedHttpClient};
use serde_json::{json, Value};
use url::Url;

use crate::{
    configured_credential, http_failure, project_http, valid_identifier, IntegrationConfigError,
    ProviderId, ProviderRead,
};

const API_HOST: &str = "console.neon.tech";
const PROJECT_LIMIT: usize = 20;
const BRANCH_LIMIT: usize = 50;

/// Read-only Neon adapter optionally pinned to one organization identifier.
#[derive(Clone)]
pub struct NeonAdapter {
    client: HardenedHttpClient,
    organization_id: Option<String>,
}

impl NeonAdapter {
    /// Constructs an adapter for personal or organization-scoped API keys.
    ///
    /// # Errors
    ///
    /// Rejects an explicitly supplied invalid organization identifier.
    pub fn new(organization_id: Option<&str>) -> Result<Self, IntegrationConfigError> {
        if organization_id.is_some_and(|value| !valid_identifier(value, 60)) {
            return Err(IntegrationConfigError::InvalidOrganizationScope);
        }
        Ok(Self {
            client: HardenedHttpClient::default(),
            organization_id: organization_id.map(str::to_owned),
        })
    }

    /// Lists a bounded project summary, optionally filtered by name or id.
    pub async fn projects(&self, search: Option<&str>, api_key: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_projects";
        let Some(api_key) = configured_credential(api_key) else {
            return ProviderRead::not_configured(ProviderId::Neon, OPERATION);
        };
        if search.is_some_and(|value| {
            value.is_empty()
                || value.len() > 100
                || value.chars().any(|character| character.is_control())
        }) {
            return ProviderRead::degraded(ProviderId::Neon, OPERATION);
        }
        let mut endpoint =
            Url::parse("https://console.neon.tech/api/v2/projects").expect("static Neon endpoint");
        {
            let mut query = endpoint.query_pairs_mut();
            query.append_pair("limit", &PROJECT_LIMIT.to_string());
            query.append_pair("timeout", "10000");
            if let Some(organization_id) = self.organization_id.as_deref() {
                query.append_pair("org_id", organization_id);
            }
            if let Some(search) = search {
                query.append_pair("search", search);
            }
        }
        self.read(OPERATION, endpoint, api_key, project_projects)
            .await
    }

    /// Lists bounded branch state for one explicitly selected Neon project.
    pub async fn branches(&self, project_id: &str, api_key: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_project_branches";
        if !valid_identifier(project_id, 60) {
            return ProviderRead::degraded(ProviderId::Neon, OPERATION);
        }
        let Some(api_key) = configured_credential(api_key) else {
            return ProviderRead::not_configured(ProviderId::Neon, OPERATION);
        };
        let mut endpoint =
            Url::parse("https://console.neon.tech/api/v2/projects/").expect("static Neon endpoint");
        endpoint
            .path_segments_mut()
            .expect("hierarchical Neon endpoint")
            .pop_if_empty()
            .push(project_id)
            .push("branches");
        self.read(OPERATION, endpoint, api_key, project_branches)
            .await
    }

    async fn read<F>(
        &self,
        operation: &'static str,
        endpoint: Url,
        api_key: &str,
        project: F,
    ) -> ProviderRead
    where
        F: FnOnce(Value) -> Option<Value>,
    {
        match self
            .client
            .get(
                endpoint.as_str(),
                &[API_HOST],
                CredentialHeaders::Bearer(api_key),
                &[("accept", "application/json")],
            )
            .await
        {
            Ok(response) => project_http(ProviderId::Neon, operation, response, project),
            Err(error) => http_failure(ProviderId::Neon, operation, error),
        }
    }
}

fn project_projects(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    let projects = object.get("projects")?.as_array()?;
    let projects = projects
        .iter()
        .take(PROJECT_LIMIT)
        .filter_map(Value::as_object)
        .map(|project| {
            json!({
                "id": project.get("id"),
                "name": project.get("name"),
                "regionId": project.get("region_id"),
                "platformId": project.get("platform_id"),
                "pgVersion": project.get("pg_version"),
                "createdAt": project.get("created_at"),
                "updatedAt": project.get("updated_at"),
            })
        })
        .collect::<Vec<_>>();
    Some(json!({
        "projects": projects,
        "truncated": object
            .get("pagination")
            .and_then(|pagination| pagination.get("cursor"))
            .is_some(),
        "unavailable": object.get("unavailable"),
    }))
}

fn project_branches(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    let branches = object.get("branches")?.as_array()?;
    Some(json!({
        "branches": branches
            .iter()
            .take(BRANCH_LIMIT)
            .filter_map(Value::as_object)
            .map(|branch| json!({
                "id": branch.get("id"),
                "name": branch.get("name"),
                "currentState": branch.get("current_state"),
                "primary": branch.get("primary"),
                "default": branch.get("default"),
                "protected": branch.get("protected"),
                "logicalSize": branch.get("logical_size"),
                "createdAt": branch.get("created_at"),
                "updatedAt": branch.get("updated_at"),
            }))
            .collect::<Vec<_>>(),
        "truncated": branches.len() > BRANCH_LIMIT,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_id_is_validated_before_requests() {
        assert!(NeonAdapter::new(Some("org-example-1")).is_ok());
        assert!(NeonAdapter::new(None).is_ok());
        assert!(NeonAdapter::new(Some("org/escape")).is_err());
    }

    #[test]
    fn project_projection_never_carries_connection_details() {
        let projected = project_projects(json!({
            "projects": [{
                "id": "project-1",
                "name": "Example",
                "region_id": "aws-us-east-1",
                "connection_uri": "postgresql://secret",
            }],
            "pagination": {},
        }))
        .expect("valid projects");
        assert_eq!(projected["projects"][0]["id"], "project-1");
        assert!(projected["projects"][0].get("connection_uri").is_none());
    }
}
