//! Supabase auth and Data API discovery reads.

use ore_mcp_http::{CredentialHeaders, HardenedHttpClient, HttpPolicy};
use serde_json::{json, Value};
use url::Url;

use crate::{
    configured_credential, http_failure, project_http, IntegrationConfigError, ProviderId,
    ProviderRead,
};

/// Read-only Supabase adapter pinned to one exact project origin.
#[derive(Clone)]
pub struct SupabaseAdapter {
    client: HardenedHttpClient,
    base_url: Url,
    exact_host: String,
}

impl SupabaseAdapter {
    /// Constructs an adapter only when the base URL matches the expected host.
    ///
    /// HTTPS is required except for exact loopback development projects. The
    /// base URL cannot carry credentials, query parameters, or fragments.
    ///
    /// # Errors
    ///
    /// Returns a value-free endpoint error for any mismatch.
    pub fn new(base_url: &str, exact_host: &str) -> Result<Self, IntegrationConfigError> {
        let base_url = HttpPolicy::default()
            .parse_base_url(base_url)
            .map_err(|_| IntegrationConfigError::InvalidEndpoint)?;
        let actual_host = base_url
            .host_str()
            .map(|value| value.trim_end_matches('.'))
            .ok_or(IntegrationConfigError::InvalidEndpoint)?;
        let exact_host = exact_host.trim().trim_end_matches('.');
        if exact_host.is_empty() || !actual_host.eq_ignore_ascii_case(exact_host) {
            return Err(IntegrationConfigError::InvalidEndpoint);
        }
        Ok(Self {
            client: HardenedHttpClient::default(),
            base_url,
            exact_host: exact_host.to_ascii_lowercase(),
        })
    }

    /// Reads a safe projection of the project's public auth configuration.
    pub async fn auth_settings(&self, api_key: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_auth_settings";
        self.read(
            OPERATION,
            "auth/v1/settings",
            api_key,
            &[("accept", "application/json")],
            project_auth_settings,
        )
        .await
    }

    /// Reads a bounded summary of the Data API's exposed OpenAPI schema.
    pub async fn data_api_schema(&self, api_key: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_data_api_schema";
        self.read(
            OPERATION,
            "rest/v1/",
            api_key,
            &[("accept", "application/openapi+json, application/json")],
            project_openapi,
        )
        .await
    }

    async fn read<F>(
        &self,
        operation: &'static str,
        path: &str,
        api_key: Option<&str>,
        headers: &[(&str, &str)],
        project: F,
    ) -> ProviderRead
    where
        F: FnOnce(Value) -> Option<Value>,
    {
        let Some(api_key) = configured_credential(api_key) else {
            return ProviderRead::not_configured(ProviderId::Supabase, operation);
        };
        let Ok(endpoint) = self.base_url.join(path) else {
            return ProviderRead::degraded(ProviderId::Supabase, operation);
        };
        match self
            .client
            .get(
                endpoint.as_str(),
                &[self.exact_host.as_str()],
                CredentialHeaders::BearerWithApiKey {
                    bearer: api_key,
                    api_key,
                },
                headers,
            )
            .await
        {
            Ok(response) => project_http(ProviderId::Supabase, operation, response, project),
            Err(error) => http_failure(ProviderId::Supabase, operation, error),
        }
    }
}

fn project_auth_settings(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    Some(json!({
        "disableSignup": object.get("disable_signup"),
        "mailerAutoconfirm": object.get("mailer_autoconfirm"),
        "phoneAutoconfirm": object.get("phone_autoconfirm"),
        "external": object.get("external"),
        "mfaEnabled": object.get("mfa_enabled"),
    }))
}

fn project_openapi(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    let paths = object.get("paths")?.as_object()?;
    let exposed_paths = paths
        .keys()
        .filter(|path| path.starts_with('/') && path.len() <= 200)
        .take(100)
        .cloned()
        .collect::<Vec<_>>();
    Some(json!({
        "openapi": object.get("openapi").or_else(|| object.get("swagger")),
        "title": object.get("info").and_then(|info| info.get("title")),
        "pathCount": paths.len(),
        "exposedPaths": exposed_paths,
        "truncated": paths.len() > 100,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_origin_must_match_exactly() {
        assert!(SupabaseAdapter::new("https://tenant.supabase.co", "tenant.supabase.co").is_ok());
        assert!(SupabaseAdapter::new("https://tenant.supabase.co", "supabase.co").is_err());
        assert!(SupabaseAdapter::new(
            "https://tenant.supabase.co.attacker.invalid",
            "tenant.supabase.co"
        )
        .is_err());
        assert!(SupabaseAdapter::new("http://127.0.0.1:54321", "127.0.0.1").is_ok());
    }

    #[test]
    fn schema_projection_is_bounded_and_useful() {
        let paths = (0..110)
            .map(|index| (format!("/table_{index}"), json!({"get": {}})))
            .collect::<serde_json::Map<_, _>>();
        let projected = project_openapi(json!({
            "openapi": "3.0.0",
            "info": {"title": "project"},
            "paths": paths,
        }))
        .expect("valid schema");
        assert_eq!(projected["pathCount"], 110);
        assert_eq!(projected["exposedPaths"].as_array().unwrap().len(), 100);
        assert_eq!(projected["truncated"], true);
    }
}
