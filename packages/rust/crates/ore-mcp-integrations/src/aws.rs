//! AWS caller-identity and EKS cluster reads using the official SDK.

use aws_sdk_eks::{error::ProvideErrorMetadata as _, Client as EksClient};
use aws_sdk_sts::Client as StsClient;
use serde_json::json;

use crate::{valid_identifier, IntegrationConfigError, IntegrationState, ProviderId, ProviderRead};

const CLUSTER_LIMIT: i32 = 100;

/// AWS adapter pinned to one account and an explicit EKS cluster allowlist.
#[derive(Clone, Debug)]
pub struct AwsAdapter {
    expected_account_id: String,
    allowed_clusters: Vec<String>,
}

impl AwsAdapter {
    /// Constructs an organization-scoped AWS adapter.
    ///
    /// # Errors
    ///
    /// The account id must contain 12 decimal digits. Cluster names are
    /// portable, unique, and bounded; an empty cluster allowlist is rejected.
    pub fn new(
        expected_account_id: impl Into<String>,
        allowed_clusters: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, IntegrationConfigError> {
        let expected_account_id = expected_account_id.into();
        let mut allowed_clusters = allowed_clusters
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        if expected_account_id.len() != 12
            || !expected_account_id
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            || allowed_clusters.is_empty()
            || allowed_clusters.len() > 100
            || allowed_clusters
                .iter()
                .any(|cluster| !valid_identifier(cluster, 100))
        {
            return Err(IntegrationConfigError::InvalidOrganizationScope);
        }
        let original_count = allowed_clusters.len();
        allowed_clusters.sort_unstable();
        allowed_clusters.dedup();
        if allowed_clusters.len() != original_count {
            return Err(IntegrationConfigError::InvalidResourceScope);
        }
        Ok(Self {
            expected_account_id,
            allowed_clusters,
        })
    }

    /// Calls STS `GetCallerIdentity` and verifies the expected AWS account.
    pub async fn caller_identity(&self, client: &StsClient) -> ProviderRead {
        const OPERATION: &str = "read_caller_identity";
        match client.get_caller_identity().send().await {
            Ok(output) => {
                let (Some(account), Some(arn), Some(user_id)) =
                    (output.account(), output.arn(), output.user_id())
                else {
                    return ProviderRead::degraded(ProviderId::Aws, OPERATION);
                };
                if account != self.expected_account_id {
                    return sdk_failure(
                        OPERATION,
                        IntegrationState::Forbidden,
                        "unexpected_aws_account",
                    );
                }
                ProviderRead::ready(
                    ProviderId::Aws,
                    OPERATION,
                    json!({
                        "account": account,
                        "arn": arn,
                        "userId": user_id,
                        "expectedAccount": true,
                    }),
                )
            }
            Err(error) => sdk_error(
                OPERATION,
                error.as_service_error().and_then(|value| value.code()),
            ),
        }
    }

    /// Lists only EKS clusters explicitly owned by this organization profile.
    pub async fn eks_clusters(&self, client: &EksClient) -> ProviderRead {
        const OPERATION: &str = "read_eks_clusters";
        match client
            .list_clusters()
            .max_results(CLUSTER_LIMIT)
            .send()
            .await
        {
            Ok(output) => {
                let clusters = output
                    .clusters()
                    .iter()
                    .filter(|cluster| self.allowed_clusters.binary_search(cluster).is_ok())
                    .cloned()
                    .collect::<Vec<_>>();
                ProviderRead::ready(
                    ProviderId::Aws,
                    OPERATION,
                    json!({
                        "clusters": clusters,
                        "allowedClusters": self.allowed_clusters,
                        "truncated": output.next_token().is_some(),
                    }),
                )
            }
            Err(error) => sdk_error(
                OPERATION,
                error.as_service_error().and_then(|value| value.code()),
            ),
        }
    }
}

fn sdk_error(operation: &'static str, code: Option<&str>) -> ProviderRead {
    let (state, diagnostic) = match code {
        Some(
            "ExpiredToken"
            | "ExpiredTokenException"
            | "InvalidClientTokenId"
            | "InvalidSignatureException"
            | "MissingAuthenticationToken"
            | "SignatureDoesNotMatch"
            | "UnrecognizedClientException",
        ) => (IntegrationState::Unauthorized, "aws_credential_rejected"),
        Some("AccessDenied" | "AccessDeniedException" | "UnauthorizedOperation") => {
            (IntegrationState::Forbidden, "aws_scope_forbidden")
        }
        Some(_) | None => (IntegrationState::Degraded, "aws_provider_unavailable"),
    };
    sdk_failure(operation, state, diagnostic)
}

fn sdk_failure(
    operation: &'static str,
    state: IntegrationState,
    diagnostic_code: &'static str,
) -> ProviderRead {
    ProviderRead {
        provider: ProviderId::Aws,
        operation,
        state,
        diagnostic_code,
        http_status: None,
        payload: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_and_cluster_scope_are_closed() {
        assert!(AwsAdapter::new("123456789012", ["ore-prod", "ore-dev"]).is_ok());
        assert!(AwsAdapter::new("not-an-account", ["ore-prod"]).is_err());
        assert!(AwsAdapter::new("123456789012", ["ore/prod"]).is_err());
        assert!(AwsAdapter::new("123456789012", ["duplicate", "duplicate"]).is_err());
    }

    #[test]
    fn sdk_codes_preserve_auth_vs_availability() {
        assert_eq!(
            sdk_error("read", Some("ExpiredToken")).state(),
            IntegrationState::Unauthorized
        );
        assert_eq!(
            sdk_error("read", Some("AccessDenied")).state(),
            IntegrationState::Forbidden
        );
        assert_eq!(
            sdk_error("read", Some("ThrottlingException")).state(),
            IntegrationState::Degraded
        );
    }
}
