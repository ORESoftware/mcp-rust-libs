//! Semantic audits for MCP initialize, tool-catalog, and text-result frames.

use std::{collections::BTreeSet, fmt, str};

use serde_json::Value;

const MAX_SESSION_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;

/// Validated metadata from one successful initialize response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializeAudit {
    /// Negotiated MCP protocol version.
    pub protocol_version: String,
    /// Non-empty server identity.
    pub server_name: String,
    /// Non-empty server release identity.
    pub server_version: String,
}

/// Validated metadata from one closed-world tools/list response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCatalogAudit {
    /// Number of tools returned.
    pub tool_count: usize,
    /// Unique tool names in response order.
    pub tool_names: Vec<String>,
}

/// Validated metadata from one text-only tools/call result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolResultAudit {
    /// Number of text content items.
    pub content_items: usize,
    /// Total UTF-8 bytes across text content.
    pub text_bytes: usize,
    /// MCP `isError` result flag.
    pub is_error: bool,
}

/// Semantic MCP session-frame validation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionAuditError {
    /// The frame was not valid UTF-8.
    NonUtf8,
    /// The frame exceeded the global audit byte bound.
    FrameTooLarge,
    /// The frame was not valid JSON.
    InvalidJson,
    /// The top-level frame was not a JSON object.
    NonObject,
    /// The frame did not declare JSON-RPC 2.0 exactly.
    MissingJsonRpcVersion,
    /// The response identifier did not match the request identifier.
    IdMismatch,
    /// The frame carried a JSON-RPC error instead of a result.
    ErrorResponse,
    /// The response had no result object.
    MissingResult,
    /// The initialize result did not negotiate an allowed protocol version.
    InvalidProtocolVersion,
    /// The initialize result had invalid or unbounded server identity metadata.
    InvalidServerInfo,
    /// The initialize result did not expose an object-shaped capabilities field.
    InvalidCapabilities,
    /// The tools/list result was not a non-empty tool array.
    InvalidToolCatalog,
    /// The tools/list result exceeded the caller's tool-count bound.
    TooManyTools,
    /// A tool name was empty, unbounded, whitespace-bearing, or control-bearing.
    InvalidToolName {
        /// Zero-based tool position.
        index: usize,
    },
    /// A tool name was repeated.
    DuplicateToolName {
        /// Zero-based position of the repeated tool.
        index: usize,
    },
    /// A tool description was missing, empty, or unbounded.
    InvalidToolDescription {
        /// Zero-based tool position.
        index: usize,
    },
    /// A tool input schema was not an object schema.
    InvalidInputSchema {
        /// Zero-based tool position.
        index: usize,
    },
    /// A tool input schema did not reject unknown properties.
    OpenInputSchema {
        /// Zero-based tool position.
        index: usize,
    },
    /// A tools/call result was not a text-content result.
    InvalidToolResult,
    /// Text content exceeded the caller's aggregate byte bound.
    TextOutputTooLarge,
}

impl fmt::Display for SessionAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SessionAuditError {}

/// Audit a successful MCP initialize response.
///
/// # Errors
///
/// Rejects malformed JSON-RPC, mismatched IDs, error responses, unsupported
/// protocol versions, missing capabilities, and invalid server identity.
pub fn audit_initialize_response(
    bytes: &[u8],
    expected_id: &Value,
    allowed_protocol_versions: &[&str],
) -> Result<InitializeAudit, SessionAuditError> {
    let result = parse_success_result(bytes, expected_id)?;
    let object = result.as_object().ok_or(SessionAuditError::MissingResult)?;
    let protocol_version =
        bounded_non_empty_string(object.get("protocolVersion"), MAX_IDENTITY_BYTES)
            .ok_or(SessionAuditError::InvalidProtocolVersion)?;
    if !allowed_protocol_versions.contains(&protocol_version) {
        return Err(SessionAuditError::InvalidProtocolVersion);
    }

    let server_info = object
        .get("serverInfo")
        .and_then(Value::as_object)
        .ok_or(SessionAuditError::InvalidServerInfo)?;
    let server_name = bounded_non_empty_string(server_info.get("name"), MAX_IDENTITY_BYTES)
        .ok_or(SessionAuditError::InvalidServerInfo)?;
    let server_version = bounded_non_empty_string(server_info.get("version"), MAX_IDENTITY_BYTES)
        .ok_or(SessionAuditError::InvalidServerInfo)?;
    if object
        .get("capabilities")
        .and_then(Value::as_object)
        .is_none()
    {
        return Err(SessionAuditError::InvalidCapabilities);
    }

    Ok(InitializeAudit {
        protocol_version: protocol_version.to_string(),
        server_name: server_name.to_string(),
        server_version: server_version.to_string(),
    })
}

/// Audit a successful tools/list response with unique, closed-world object schemas.
///
/// # Errors
///
/// Rejects malformed JSON-RPC, mismatched IDs, empty or oversized catalogs,
/// invalid names/descriptions, duplicate names, and open input schemas.
pub fn audit_closed_world_tool_catalog_response(
    bytes: &[u8],
    expected_id: &Value,
    max_tools: usize,
) -> Result<ToolCatalogAudit, SessionAuditError> {
    let result = parse_success_result(bytes, expected_id)?;
    let tools = result
        .as_object()
        .and_then(|object| object.get("tools"))
        .and_then(Value::as_array)
        .ok_or(SessionAuditError::InvalidToolCatalog)?;
    if tools.is_empty() {
        return Err(SessionAuditError::InvalidToolCatalog);
    }
    if tools.len() > max_tools {
        return Err(SessionAuditError::TooManyTools);
    }

    let mut seen = BTreeSet::new();
    let mut tool_names = Vec::with_capacity(tools.len());
    for (index, tool) in tools.iter().enumerate() {
        let tool = tool
            .as_object()
            .ok_or(SessionAuditError::InvalidToolCatalog)?;
        let name = bounded_non_empty_string(tool.get("name"), MAX_TOOL_NAME_BYTES)
            .filter(|name| {
                !name
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            })
            .ok_or(SessionAuditError::InvalidToolName { index })?;
        bounded_non_empty_string(tool.get("description"), MAX_TOOL_DESCRIPTION_BYTES)
            .ok_or(SessionAuditError::InvalidToolDescription { index })?;

        let schema = tool
            .get("inputSchema")
            .and_then(Value::as_object)
            .ok_or(SessionAuditError::InvalidInputSchema { index })?;
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(SessionAuditError::InvalidInputSchema { index });
        }
        if schema.get("additionalProperties").and_then(Value::as_bool) != Some(false) {
            return Err(SessionAuditError::OpenInputSchema { index });
        }
        if !seen.insert(name.to_string()) {
            return Err(SessionAuditError::DuplicateToolName { index });
        }
        tool_names.push(name.to_string());
    }

    Ok(ToolCatalogAudit {
        tool_count: tool_names.len(),
        tool_names,
    })
}

/// Audit a successful text-only tools/call response under an aggregate byte limit.
///
/// # Errors
///
/// Rejects malformed JSON-RPC, mismatched IDs, non-text content, invalid
/// `isError` values, arithmetic overflow, and aggregate text over the limit.
pub fn audit_text_tool_result_response(
    bytes: &[u8],
    expected_id: &Value,
    max_text_bytes: usize,
) -> Result<ToolResultAudit, SessionAuditError> {
    let result = parse_success_result(bytes, expected_id)?;
    let result = result
        .as_object()
        .ok_or(SessionAuditError::InvalidToolResult)?;
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .ok_or(SessionAuditError::InvalidToolResult)?;
    if content.is_empty() {
        return Err(SessionAuditError::InvalidToolResult);
    }
    let is_error = match result.get("isError") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or(SessionAuditError::InvalidToolResult)?,
    };

    let mut text_bytes = 0_usize;
    for item in content {
        let item = item
            .as_object()
            .ok_or(SessionAuditError::InvalidToolResult)?;
        if item.get("type").and_then(Value::as_str) != Some("text") {
            return Err(SessionAuditError::InvalidToolResult);
        }
        let text = item
            .get("text")
            .and_then(Value::as_str)
            .ok_or(SessionAuditError::InvalidToolResult)?;
        text_bytes = text_bytes
            .checked_add(text.len())
            .ok_or(SessionAuditError::TextOutputTooLarge)?;
        if text_bytes > max_text_bytes {
            return Err(SessionAuditError::TextOutputTooLarge);
        }
    }

    Ok(ToolResultAudit {
        content_items: content.len(),
        text_bytes,
        is_error,
    })
}

fn parse_success_result(bytes: &[u8], expected_id: &Value) -> Result<Value, SessionAuditError> {
    if bytes.len() > MAX_SESSION_FRAME_BYTES {
        return Err(SessionAuditError::FrameTooLarge);
    }
    let text = str::from_utf8(bytes).map_err(|_| SessionAuditError::NonUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| SessionAuditError::InvalidJson)?;
    let object = value.as_object().ok_or(SessionAuditError::NonObject)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(SessionAuditError::MissingJsonRpcVersion);
    }
    if object.get("id") != Some(expected_id) {
        return Err(SessionAuditError::IdMismatch);
    }
    if object.contains_key("error") {
        return Err(SessionAuditError::ErrorResponse);
    }
    object
        .get("result")
        .cloned()
        .ok_or(SessionAuditError::MissingResult)
}

fn bounded_non_empty_string(value: Option<&Value>, max_bytes: usize) -> Option<&str> {
    value.and_then(Value::as_str).filter(|text| {
        !text.trim().is_empty() && text.len() <= max_bytes && !text.chars().any(char::is_control)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn bytes(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("test JSON")
    }

    #[test]
    fn initialize_response_negotiates_an_allowed_version() {
        let frame = bytes(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-11-25",
                "serverInfo": {
                    "name": "example-mcp",
                    "version": "1.2.3"
                },
                "capabilities": {
                    "tools": {}
                }
            }
        }));
        let audit = audit_initialize_response(&frame, &json!(1), &["2025-06-18", "2025-11-25"])
            .expect("valid initialize response");
        assert_eq!(audit.protocol_version, "2025-11-25");
        assert_eq!(audit.server_name, "example-mcp");
        assert_eq!(audit.server_version, "1.2.3");
    }

    #[test]
    fn initialize_response_rejects_version_and_rpc_errors() {
        let unsupported = bytes(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "old", "version": "1"},
                "capabilities": {}
            }
        }));
        assert_eq!(
            audit_initialize_response(&unsupported, &json!(1), &["2025-11-25"]),
            Err(SessionAuditError::InvalidProtocolVersion)
        );

        let error = bytes(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32603, "message": "internal"}
        }));
        assert_eq!(
            audit_initialize_response(&error, &json!(1), &["2025-11-25"]),
            Err(SessionAuditError::ErrorResponse)
        );
    }

    #[test]
    fn closed_world_tool_catalog_passes() {
        let frame = bytes(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "result": {
                "tools": [
                    {
                        "name": "org_map",
                        "description": "Return an organization map.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": false
                        }
                    },
                    {
                        "name": "list_items",
                        "description": "List bounded items.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "limit": {"type": "integer"}
                            },
                            "additionalProperties": false
                        }
                    }
                ]
            }
        }));
        let audit = audit_closed_world_tool_catalog_response(&frame, &json!("tools"), 10)
            .expect("valid tool catalog");
        assert_eq!(audit.tool_count, 2);
        assert_eq!(
            audit.tool_names,
            vec!["org_map".to_string(), "list_items".to_string()]
        );
    }

    #[test]
    fn duplicate_and_open_tool_schemas_are_rejected() {
        let duplicate = bytes(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "same",
                        "description": "First.",
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": false
                        }
                    },
                    {
                        "name": "same",
                        "description": "Second.",
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": false
                        }
                    }
                ]
            }
        }));
        assert_eq!(
            audit_closed_world_tool_catalog_response(&duplicate, &json!(2), 10),
            Err(SessionAuditError::DuplicateToolName { index: 1 })
        );

        let open = bytes(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [{
                    "name": "open",
                    "description": "Open input.",
                    "inputSchema": {"type": "object"}
                }]
            }
        }));
        assert_eq!(
            audit_closed_world_tool_catalog_response(&open, &json!(2), 10),
            Err(SessionAuditError::OpenInputSchema { index: 0 })
        );
    }

    #[test]
    fn text_tool_results_are_aggregate_bounded() {
        let frame = bytes(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "content": [
                    {"type": "text", "text": "abc"},
                    {"type": "text", "text": "def"}
                ],
                "isError": false
            }
        }));
        let audit = audit_text_tool_result_response(&frame, &json!(3), 6).expect("bounded text");
        assert_eq!(
            audit,
            ToolResultAudit {
                content_items: 2,
                text_bytes: 6,
                is_error: false,
            }
        );
        assert_eq!(
            audit_text_tool_result_response(&frame, &json!(3), 5),
            Err(SessionAuditError::TextOutputTooLarge)
        );
    }

    #[test]
    fn non_text_tool_results_are_rejected() {
        let frame = bytes(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "content": [{"type": "image", "data": "opaque"}]
            }
        }));
        assert_eq!(
            audit_text_tool_result_response(&frame, &json!(3), 1024),
            Err(SessionAuditError::InvalidToolResult)
        );
    }
}
