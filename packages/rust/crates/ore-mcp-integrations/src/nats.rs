//! NATS request/reply reads over an explicit subject allowlist.

use std::time::Duration;

use async_nats::Client;
use serde_json::{json, Value};

use crate::{IntegrationConfigError, ProviderId, ProviderRead};

const MAX_SUBJECTS: usize = 100;
const MAX_CHECKS: usize = 50;

/// NATS adapter for the closed `ore.mcp.read.v1` response envelope.
#[derive(Clone, Debug)]
pub struct NatsAdapter {
    allowed_subjects: Vec<String>,
    timeout: Duration,
    response_max_bytes: usize,
}

impl NatsAdapter {
    /// Constructs a bounded exact-subject adapter.
    ///
    /// # Errors
    ///
    /// Wildcards, empty/duplicate subjects, deadlines outside 100 ms through
    /// 60 seconds, and response limits outside 1 KiB through 1 MiB are rejected.
    pub fn new(
        allowed_subjects: impl IntoIterator<Item = impl Into<String>>,
        timeout: Duration,
        response_max_bytes: usize,
    ) -> Result<Self, IntegrationConfigError> {
        let mut allowed_subjects = allowed_subjects
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        if allowed_subjects.is_empty()
            || allowed_subjects.len() > MAX_SUBJECTS
            || allowed_subjects.iter().any(|value| !valid_subject(value))
        {
            return Err(IntegrationConfigError::InvalidResourceScope);
        }
        let original_count = allowed_subjects.len();
        allowed_subjects.sort_unstable();
        allowed_subjects.dedup();
        if allowed_subjects.len() != original_count {
            return Err(IntegrationConfigError::InvalidResourceScope);
        }
        if timeout < Duration::from_millis(100)
            || timeout > Duration::from_secs(60)
            || !(1024..=1024 * 1024).contains(&response_max_bytes)
        {
            return Err(IntegrationConfigError::InvalidLimit);
        }
        Ok(Self {
            allowed_subjects,
            timeout,
            response_max_bytes,
        })
    }

    /// Requests the fixed organization-service snapshot operation.
    pub async fn service_snapshot(&self, client: Option<&Client>, subject: &str) -> ProviderRead {
        self.request(client, subject, "read_service_snapshot", "service_snapshot")
            .await
    }

    /// Requests the fixed organization dependency-readiness operation.
    pub async fn dependency_snapshot(
        &self,
        client: Option<&Client>,
        subject: &str,
    ) -> ProviderRead {
        self.request(
            client,
            subject,
            "read_dependency_snapshot",
            "dependency_snapshot",
        )
        .await
    }

    async fn request(
        &self,
        client: Option<&Client>,
        subject: &str,
        operation: &'static str,
        wire_operation: &'static str,
    ) -> ProviderRead {
        if self
            .allowed_subjects
            .binary_search_by(|value| value.as_str().cmp(subject))
            .is_err()
        {
            return ProviderRead::degraded(ProviderId::Nats, operation);
        }
        let Some(client) = client else {
            return ProviderRead::not_configured(ProviderId::Nats, operation);
        };
        let request = json!({
            "schema": "ore.mcp.read.v1",
            "operation": wire_operation,
        })
        .to_string();
        let response = match tokio::time::timeout(
            self.timeout,
            client.request(subject.to_owned(), request.into()),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return ProviderRead::degraded(ProviderId::Nats, operation),
        };
        if response.payload.len() > self.response_max_bytes {
            return ProviderRead::degraded(ProviderId::Nats, operation);
        }
        let Some(payload) = serde_json::from_slice(response.payload.as_ref())
            .ok()
            .and_then(project_snapshot)
        else {
            return ProviderRead::degraded(ProviderId::Nats, operation);
        };
        ProviderRead::ready(ProviderId::Nats, operation, payload)
    }
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 300
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains(['*', '>', ' '])
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

fn project_snapshot(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    if object.get("schema")?.as_str()? != "ore.mcp.read.v1" {
        return None;
    }
    let service = object.get("service")?.as_str()?;
    let status = object.get("status")?.as_str()?;
    if service.is_empty()
        || service.len() > 128
        || status.is_empty()
        || status.len() > 32
        || !service.chars().all(|character| !character.is_control())
        || !status.chars().all(|character| !character.is_control())
    {
        return None;
    }
    let checks = object
        .get("checks")
        .and_then(Value::as_array)
        .map(|checks| {
            checks
                .iter()
                .take(MAX_CHECKS)
                .filter_map(Value::as_object)
                .map(|check| {
                    json!({
                        "name": check.get("name"),
                        "status": check.get("status"),
                        "summary": check.get("summary"),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(json!({
        "schema": "ore.mcp.read.v1",
        "service": service,
        "status": status,
        "version": object.get("version"),
        "summary": object.get("summary"),
        "checks": checks,
        "checksTruncated": object
            .get("checks")
            .and_then(Value::as_array)
            .is_some_and(|value| value.len() > MAX_CHECKS),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_are_exact_and_wildcards_are_rejected() {
        let adapter = NatsAdapter::new(["threefa.mcp.read"], Duration::from_secs(2), 64 * 1024)
            .expect("valid adapter");
        assert_eq!(adapter.allowed_subjects, ["threefa.mcp.read"]);
        assert!(NatsAdapter::new(["threefa.>"], Duration::from_secs(2), 64 * 1024,).is_err());
    }

    #[test]
    fn snapshot_projection_is_closed_and_bounded() {
        let projected = project_snapshot(json!({
            "schema": "ore.mcp.read.v1",
            "service": "threefa-api",
            "status": "ready",
            "summary": "all dependencies are ready",
            "credential": "never-return",
            "checks": [{"name": "database", "status": "ready", "details": "private"}],
        }))
        .expect("valid snapshot");
        assert_eq!(projected["service"], "threefa-api");
        assert!(projected.get("credential").is_none());
        assert!(projected["checks"][0].get("details").is_none());
    }
}
