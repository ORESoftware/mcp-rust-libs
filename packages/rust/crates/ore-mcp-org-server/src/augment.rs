//! Composition of the fleet parity surface with richer organization handlers.

#![expect(
    deprecated,
    reason = "delegating rmcp 2.2 logging hooks preserves primary handler behavior"
)]

use std::collections::BTreeSet;
use std::io;

use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{ErrorData, RoleServer, ServerHandler};

use crate::{OrgMcpServer, OrgSpec};

/// Exact shared tools added to every rich organization MCP server.
pub const PARITY_TOOL_NAMES: &[&str] = &[
    "aws_posture",
    "cloudflare_posture",
    "environment_policy",
    "gcp_posture",
    "github_posture",
    "k8s_posture",
    "nats_posture",
    "neon_posture",
    "org_identity",
    "organization_posture",
    "security_baseline",
    "shared_auth_policy",
    "supabase_posture",
    "telemetry_status",
    "zed_dependency_graph",
];

const PARITY_PROMPT_NAMES: &[&str] = &["dependency_review", "deploy_readiness", "provider_triage"];

/// A handler that preserves an org-specific MCP surface and adds fleet parity.
///
/// Tool-name collisions fail during construction so an older domain tool can
/// never silently replace a hardened provider tool. Resource and prompt name
/// collisions intentionally retain the primary handler's richer content.
#[derive(Clone)]
pub struct ParityAugmented<S> {
    primary: S,
    parity: OrgMcpServer,
    organization: &'static str,
}

impl<S> ParityAugmented<S>
where
    S: ServerHandler + Clone,
{
    /// Validates and composes a primary handler with the shared parity handler.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid organization spec or any shared tool
    /// name already owned by the primary handler.
    pub fn new(primary: S, spec: OrgSpec) -> io::Result<Self> {
        if let Some(name) = PARITY_TOOL_NAMES
            .iter()
            .find(|name| primary.get_tool(name).is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("primary MCP handler collides with parity tool {name}"),
            ));
        }
        Ok(Self {
            primary,
            parity: OrgMcpServer::embedded(spec)?,
            organization: spec.organization,
        })
    }

    /// Returns the untouched primary handler.
    #[must_use]
    pub const fn primary(&self) -> &S {
        &self.primary
    }

    /// Consumes the composition and returns the primary handler.
    #[must_use]
    pub fn into_primary(self) -> S {
        self.primary
    }

    fn parity_resource(&self, uri: &str) -> bool {
        uri == format!("orgmap://{}", self.organization)
            || uri == format!("contract://{}/mcp-clients", self.organization)
            || uri == format!("contract://{}/providers", self.organization)
    }
}

fn merge_tools(mut primary: ListToolsResult, parity: ListToolsResult) -> ListToolsResult {
    let mut names = primary
        .tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect::<BTreeSet<_>>();
    primary.tools.extend(
        parity
            .tools
            .into_iter()
            .filter(|tool| names.insert(tool.name.to_string())),
    );
    primary
        .tools
        .sort_by(|left, right| left.name.cmp(&right.name));
    primary.next_cursor = primary.next_cursor.or(parity.next_cursor);
    primary.meta = primary.meta.or(parity.meta);
    primary
}

fn merge_resources(
    mut primary: ListResourcesResult,
    parity: ListResourcesResult,
) -> ListResourcesResult {
    let mut uris = primary
        .resources
        .iter()
        .map(|resource| resource.uri.clone())
        .collect::<BTreeSet<_>>();
    primary.resources.extend(
        parity
            .resources
            .into_iter()
            .filter(|resource| uris.insert(resource.uri.clone())),
    );
    primary
        .resources
        .sort_by(|left, right| left.uri.cmp(&right.uri));
    primary.next_cursor = primary.next_cursor.or(parity.next_cursor);
    primary.meta = primary.meta.or(parity.meta);
    primary
}

fn merge_prompts(mut primary: ListPromptsResult, parity: ListPromptsResult) -> ListPromptsResult {
    let mut names = primary
        .prompts
        .iter()
        .map(|prompt| prompt.name.clone())
        .collect::<BTreeSet<_>>();
    primary.prompts.extend(
        parity
            .prompts
            .into_iter()
            .filter(|prompt| names.insert(prompt.name.clone())),
    );
    primary
        .prompts
        .sort_by(|left, right| left.name.cmp(&right.name));
    primary.next_cursor = primary.next_cursor.or(parity.next_cursor);
    primary.meta = primary.meta.or(parity.meta);
    primary
}

fn parity_tool(name: &str) -> bool {
    PARITY_TOOL_NAMES.binary_search(&name).is_ok()
}

fn parity_prompt(name: &str) -> bool {
    PARITY_PROMPT_NAMES.binary_search(&name).is_ok()
}

impl<S> ServerHandler for ParityAugmented<S>
where
    S: ServerHandler + Clone,
{
    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        self.primary.ping(context).await
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        self.primary.complete(request, context).await
    }

    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.primary.set_level(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        if parity_tool(&request.name) {
            self.parity.call_tool(request, context).await
        } else {
            self.primary.call_tool(request, context).await
        }
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let primary = self
            .primary
            .list_tools(request.clone(), context.clone())
            .await?;
        let parity = self.parity.list_tools(request, context).await?;
        Ok(merge_tools(primary, parity))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        if parity_tool(name) {
            self.parity.get_tool(name)
        } else {
            self.primary.get_tool(name)
        }
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let primary = self
            .primary
            .list_resources(request.clone(), context.clone())
            .await?;
        let parity = self.parity.list_resources(request, context).await?;
        Ok(merge_resources(primary, parity))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        if self.parity_resource(&request.uri) {
            if let Ok(result) = self
                .primary
                .read_resource(request.clone(), context.clone())
                .await
            {
                return Ok(result);
            }
            self.parity.read_resource(request, context).await
        } else {
            self.primary.read_resource(request, context).await
        }
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.primary.list_resource_templates(request, context).await
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.primary.subscribe(request, context).await
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.primary.unsubscribe(request, context).await
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let primary = self
            .primary
            .list_prompts(request.clone(), context.clone())
            .await?;
        let parity = self.parity.list_prompts(request, context).await?;
        Ok(merge_prompts(primary, parity))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        if parity_prompt(&request.name) {
            if let Ok(result) = self
                .primary
                .get_prompt(request.clone(), context.clone())
                .await
            {
                return Ok(result);
            }
            self.parity.get_prompt(request, context).await
        } else {
            self.primary.get_prompt(request, context).await
        }
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        self.primary.on_custom_request(request, context).await
    }

    async fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CreateTaskResult, ErrorData> {
        self.primary.enqueue_task(request, context).await
    }

    async fn list_tasks(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListTasksResult, ErrorData> {
        self.primary.list_tasks(request, context).await
    }

    async fn get_task_info(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        self.primary.get_task_info(request, context).await
    }

    async fn get_task_result(
        &self,
        request: GetTaskPayloadParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskPayloadResult, ErrorData> {
        self.primary.get_task_result(request, context).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CancelTaskResult, ErrorData> {
        self.primary.cancel_task(request, context).await
    }

    async fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.primary.on_cancelled(notification, context).await;
    }

    async fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.primary.on_progress(notification, context).await;
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.primary.on_initialized(context).await;
    }

    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) {
        self.primary.on_roots_list_changed(context).await;
    }

    async fn on_task_status(
        &self,
        params: TaskStatusNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.primary.on_task_status(params, context).await;
    }

    async fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) {
        self.primary
            .on_custom_notification(notification, context)
            .await;
    }

    fn get_info(&self) -> ServerInfo {
        let mut primary = self.primary.get_info();
        let parity = self.parity.get_info();
        primary.protocol_version = ProtocolVersion::V_2025_11_25;
        primary.capabilities.tools = primary.capabilities.tools.or(parity.capabilities.tools);
        primary.capabilities.resources = primary
            .capabilities
            .resources
            .or(parity.capabilities.resources);
        primary.capabilities.prompts = primary.capabilities.prompts.or(parity.capabilities.prompts);
        if let Some(parity_instructions) = parity.instructions {
            primary.instructions = Some(match primary.instructions {
                Some(instructions) if !instructions.is_empty() => {
                    format!("{instructions}\n\n{parity_instructions}")
                }
                _ => parity_instructions,
            });
        }
        primary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct DomainServer;

    impl ServerHandler for DomainServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
                .with_server_info(Implementation::new("domain-server", "1.0.0"))
                .with_instructions("Keep the domain-specific surface.")
        }
    }

    const DEPENDENCIES: &[&str] = &["shared-auth/shared-auth-clients"];

    fn spec() -> OrgSpec {
        OrgSpec {
            organization: "example-org",
            repository: "example-org/example-mcp-server.rs",
            service_name: "example-mcp-server",
            package_name: "example-mcp-server",
            dependencies: DEPENDENCIES,
            version: "1.0.0",
        }
    }

    #[test]
    fn augmented_info_preserves_primary_identity_and_adds_final_parity() {
        let server = ParityAugmented::new(DomainServer, spec()).expect("compose handlers");
        let info = server.get_info();
        assert_eq!(info.server_info.name, "domain-server");
        assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.resources.is_some());
        assert!(info.capabilities.prompts.is_some());
        let instructions = info.instructions.expect("combined instructions");
        assert!(instructions.contains("domain-specific"));
        assert!(instructions.contains("organization_posture"));
    }

    #[test]
    fn parity_names_and_scopes_are_exact() {
        assert!(parity_tool("organization_posture"));
        assert!(!parity_tool("domain_tool"));
        assert!(parity_prompt("provider_triage"));
        let server = ParityAugmented::new(DomainServer, spec()).expect("compose handlers");
        assert!(server.parity_resource("orgmap://example-org"));
        assert!(!server.parity_resource("orgmap://other"));
    }
}
