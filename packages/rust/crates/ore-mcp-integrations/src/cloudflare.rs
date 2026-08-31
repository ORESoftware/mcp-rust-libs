//! Cloudflare zone and DNS reads scoped to explicit organization domains.

use ore_mcp_http::{CredentialHeaders, HardenedHttpClient};
use serde_json::{json, Value};
use url::Url;

use crate::{
    configured_credential, http_failure, project_http, valid_identifier, IntegrationConfigError,
    ProviderId, ProviderRead,
};

const API_HOST: &str = "api.cloudflare.com";
const RECORD_LIMIT: usize = 100;

/// Read-only Cloudflare adapter with an immutable domain allowlist.
#[derive(Clone)]
pub struct CloudflareAdapter {
    client: HardenedHttpClient,
    allowed_zones: Vec<String>,
}

impl CloudflareAdapter {
    /// Constructs an adapter for one or more exact DNS zone names.
    ///
    /// # Errors
    ///
    /// Empty, duplicate, wildcard, and malformed zone names are rejected.
    pub fn new(
        allowed_zones: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, IntegrationConfigError> {
        let mut allowed_zones = allowed_zones
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        if allowed_zones.is_empty()
            || allowed_zones.len() > 32
            || allowed_zones.iter().any(|zone| !valid_zone(zone))
        {
            return Err(IntegrationConfigError::InvalidOrganizationScope);
        }
        let original_count = allowed_zones.len();
        allowed_zones.sort_unstable();
        allowed_zones.dedup();
        if allowed_zones.len() != original_count {
            return Err(IntegrationConfigError::InvalidOrganizationScope);
        }
        Ok(Self {
            client: HardenedHttpClient::default(),
            allowed_zones,
        })
    }

    /// Reads one explicitly allowed zone, never the caller's entire account.
    pub async fn zone(&self, name: &str, api_token: Option<&str>) -> ProviderRead {
        const OPERATION: &str = "read_zone";
        if !self.is_allowed_zone(name) {
            return ProviderRead::degraded(ProviderId::Cloudflare, OPERATION);
        }
        let Some(api_token) = configured_credential(api_token) else {
            return ProviderRead::not_configured(ProviderId::Cloudflare, OPERATION);
        };
        let mut endpoint = Url::parse("https://api.cloudflare.com/client/v4/zones")
            .expect("static Cloudflare endpoint");
        endpoint.query_pairs_mut().append_pair("name", name);
        self.read(OPERATION, endpoint, api_token, project_zone)
            .await
    }

    /// Reads bounded DNS metadata for one allowed zone.
    ///
    /// Record content is omitted because TXT and service records commonly carry
    /// verification material. The projection still exposes names, types,
    /// routing/proxy posture, TTL, and timestamps.
    pub async fn dns_records(
        &self,
        zone_name: &str,
        zone_id: &str,
        api_token: Option<&str>,
    ) -> ProviderRead {
        const OPERATION: &str = "read_dns_records";
        if !self.is_allowed_zone(zone_name) || !valid_identifier(zone_id, 64) {
            return ProviderRead::degraded(ProviderId::Cloudflare, OPERATION);
        }
        let Some(api_token) = configured_credential(api_token) else {
            return ProviderRead::not_configured(ProviderId::Cloudflare, OPERATION);
        };
        let mut endpoint = Url::parse("https://api.cloudflare.com/client/v4/zones/")
            .expect("static Cloudflare endpoint");
        endpoint
            .path_segments_mut()
            .expect("hierarchical Cloudflare endpoint")
            .pop_if_empty()
            .push(zone_id)
            .push("dns_records");
        endpoint
            .query_pairs_mut()
            .append_pair("per_page", &RECORD_LIMIT.to_string());
        self.read(OPERATION, endpoint, api_token, project_records)
            .await
    }

    fn is_allowed_zone(&self, candidate: &str) -> bool {
        self.allowed_zones
            .iter()
            .any(|zone| zone.eq_ignore_ascii_case(candidate))
    }

    async fn read<F>(
        &self,
        operation: &'static str,
        endpoint: Url,
        api_token: &str,
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
                CredentialHeaders::Bearer(api_token),
                &[("accept", "application/json")],
            )
            .await
        {
            Ok(response) => project_http(ProviderId::Cloudflare, operation, response, project),
            Err(error) => http_failure(ProviderId::Cloudflare, operation, error),
        }
    }
}

fn valid_zone(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains('*')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn successful_result(value: &Value) -> Option<&Value> {
    value
        .get("success")?
        .as_bool()?
        .then(|| value.get("result"))
        .flatten()
}

fn project_zone(value: Value) -> Option<Value> {
    let zones = successful_result(&value)?.as_array()?;
    let zones = zones
        .iter()
        .take(2)
        .filter_map(Value::as_object)
        .map(|zone| {
            json!({
                "id": zone.get("id"),
                "name": zone.get("name"),
                "status": zone.get("status"),
                "paused": zone.get("paused"),
                "type": zone.get("type"),
                "nameServers": zone.get("name_servers"),
                "modifiedOn": zone.get("modified_on"),
                "accountId": zone.get("account").and_then(|account| account.get("id")),
            })
        })
        .collect::<Vec<_>>();
    Some(json!({"zones": zones}))
}

fn project_records(value: Value) -> Option<Value> {
    let records = successful_result(&value)?.as_array()?;
    Some(json!({
        "records": records
            .iter()
            .take(RECORD_LIMIT)
            .filter_map(Value::as_object)
            .map(|record| json!({
                "id": record.get("id"),
                "type": record.get("type"),
                "name": record.get("name"),
                "proxied": record.get("proxied"),
                "proxiable": record.get("proxiable"),
                "ttl": record.get("ttl"),
                "comment": record.get("comment"),
                "modifiedOn": record.get("modified_on"),
            }))
            .collect::<Vec<_>>(),
        "truncated": records.len() > RECORD_LIMIT,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_allowlist_is_exact_and_wildcard_free() {
        let adapter =
            CloudflareAdapter::new(["example.com", "api.example.com"]).expect("valid zones");
        assert!(adapter.is_allowed_zone("EXAMPLE.COM"));
        assert!(!adapter.is_allowed_zone("example.com.attacker.invalid"));
        assert!(CloudflareAdapter::new(["*.example.com"]).is_err());
    }

    #[test]
    fn dns_projection_never_returns_record_content() {
        let projected = project_records(json!({
            "success": true,
            "result": [{
                "id": "record-1",
                "type": "TXT",
                "name": "_verify.example.com",
                "content": "verification-secret",
                "ttl": 300,
            }]
        }))
        .expect("valid records");
        assert_eq!(projected["records"][0]["type"], "TXT");
        assert!(projected["records"][0].get("content").is_none());
    }
}
