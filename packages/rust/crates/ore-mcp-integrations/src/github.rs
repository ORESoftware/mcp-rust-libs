//! GitHub organization and workflow reads.

use ore_mcp_http::{CredentialHeaders, HardenedHttpClient};
use serde_json::{json, Value};

use crate::{
    configured_credential, http_failure, project_http, valid_identifier, IntegrationConfigError,
    ProviderId, ProviderRead,
};

const API_HOST: &str = "api.github.com";
const ACCEPT: &[(&str, &str)] = &[
    ("accept", "application/vnd.github+json"),
    ("x-github-api-version", "2022-11-28"),
];

/// Read-only GitHub adapter pinned to one organization.
#[derive(Clone)]
pub struct GitHubAdapter {
    client: HardenedHttpClient,
    organization: String,
}

impl GitHubAdapter {
    /// Constructs an adapter for one exact GitHub organization login.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-portable organization names.
    pub fn new(organization: impl Into<String>) -> Result<Self, IntegrationConfigError> {
        let organization = organization.into();
        if !valid_identifier(&organization, 100) {
            return Err(IntegrationConfigError::InvalidOrganizationScope);
        }
        Ok(Self {
            client: HardenedHttpClient::default(),
            organization,
        })
    }

    /// Reads a bounded projection of the configured GitHub organization.
    pub async fn organization(&self, token: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_organization";
        let Some(token) = configured_credential(token) else {
            return ProviderRead::not_configured(ProviderId::GitHub, OPERATION);
        };
        let endpoint = format!("https://{API_HOST}/orgs/{}", self.organization);
        match self
            .client
            .get(
                &endpoint,
                &[API_HOST],
                CredentialHeaders::Bearer(token),
                ACCEPT,
            )
            .await
        {
            Ok(response) => project_http(
                ProviderId::GitHub,
                OPERATION,
                response,
                project_organization,
            ),
            Err(error) => http_failure(ProviderId::GitHub, OPERATION, error),
        }
    }

    /// Reads the latest Actions run for one repository in the configured org.
    pub async fn latest_workflow_run(&self, repository: &str, token: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_latest_workflow_run";
        if !valid_identifier(repository, 100) {
            return ProviderRead::degraded(ProviderId::GitHub, OPERATION);
        }
        let Some(token) = configured_credential(token) else {
            return ProviderRead::not_configured(ProviderId::GitHub, OPERATION);
        };
        let endpoint = format!(
            "https://{API_HOST}/repos/{}/{repository}/actions/runs?per_page=1",
            self.organization
        );
        match self
            .client
            .get(
                &endpoint,
                &[API_HOST],
                CredentialHeaders::Bearer(token),
                ACCEPT,
            )
            .await
        {
            Ok(response) => {
                project_http(ProviderId::GitHub, OPERATION, response, project_latest_run)
            }
            Err(error) => http_failure(ProviderId::GitHub, OPERATION, error),
        }
    }
}

fn project_organization(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    object.get("login")?.as_str()?;
    Some(json!({
        "login": object.get("login"),
        "id": object.get("id"),
        "name": object.get("name"),
        "description": object.get("description"),
        "publicRepos": object.get("public_repos"),
        "htmlUrl": object.get("html_url"),
        "updatedAt": object.get("updated_at"),
    }))
}

fn project_latest_run(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    let runs = object.get("workflow_runs")?.as_array()?;
    let latest = runs.first().and_then(Value::as_object).map(|run| {
        json!({
            "id": run.get("id"),
            "name": run.get("name"),
            "displayTitle": run.get("display_title"),
            "event": run.get("event"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "runNumber": run.get("run_number"),
            "headSha": run.get("head_sha"),
            "htmlUrl": run.get("html_url"),
            "createdAt": run.get("created_at"),
            "updatedAt": run.get("updated_at"),
        })
    });
    Some(json!({
        "totalCount": object.get("total_count"),
        "latest": latest,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_scope_is_closed() {
        assert!(GitHubAdapter::new("ORESoftware").is_ok());
        assert!(GitHubAdapter::new("owner/another").is_err());
        assert!(GitHubAdapter::new("bad\nowner").is_err());
    }

    #[test]
    fn projections_drop_unbounded_or_sensitive_fields() {
        let projected = project_organization(json!({
            "login": "ORESoftware",
            "id": 1,
            "public_repos": 12,
            "html_url": "https://github.com/ORESoftware",
            "updated_at": "2026-08-31T00:00:00Z",
            "plan": {"private_repos": 999},
            "email": "private@example.invalid"
        }))
        .expect("valid projection");
        assert_eq!(projected["login"], "ORESoftware");
        assert!(projected.get("plan").is_none());
        assert!(projected.get("email").is_none());
    }

    #[test]
    fn empty_workflow_history_is_a_real_empty_result() {
        let projected = project_latest_run(json!({
            "total_count": 0,
            "workflow_runs": [],
        }))
        .expect("valid workflow response");
        assert_eq!(projected["totalCount"], 0);
        assert!(projected["latest"].is_null());
    }
}
