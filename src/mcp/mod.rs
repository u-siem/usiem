//! Tier-1 MCP support: the **data model only**.
//!
//! [`McpSurface`] turns a [`crate::capability::CapabilityCatalog`] (filtered
//! through a [`crate::security::Authorizer`]) into MCP's own vocabulary —
//! [`McpTool`]s (from [`crate::processing::action::ActionDescriptor`]s),
//! [`McpResource`]s (from [`crate::capability::ComponentManifest`]s), and
//! [`McpPrompt`]s (from [`crate::processing::message::TemplateRegistry`]) —
//! and can execute a tool call end to end, JSON arguments in, a
//! [`CallToolResult`] out.
//!
//! # What is deliberately *not* here
//!
//! No JSON-RPC 2.0 framing, no stdio/Streamable HTTP transport, no OAuth
//! resource-server flow. "Internal building blocks in, communication out":
//! this module never opens a socket, reads stdin, or sees an HTTP request.
//! A satellite crate (e.g. `usiem-mcp-server`) is expected to depend on an
//! async runtime and a real MCP SDK, wrap this module's types in the wire
//! protocol, and turn an authenticated caller's credentials into the
//! [`crate::processing::context::InvocationContext`] every method here
//! takes — authentication is exactly as out of scope for this module as it
//! is for [`crate::security`], for the same reason (see that module's
//! docs).
//!
//! # Tool naming and multi-provider fan-out
//!
//! [`crate::processing::action::ActionRegistry`] lets many providers share
//! one capability name (`"block_ip"` implemented by both `firewall` and
//! `edr`). [`McpSurface::list_tools`]/[`McpSurface::call_tool`] resolve that
//! the same way for every capability name:
//! - One provider, or several providers whose [`crate::event::Schema::to_json_schema`]
//!   output is identical: **one tool**, named after the capability
//!   (`"block_ip"`). Calling it fans out to every provider via
//!   [`crate::processing::action::ActionRegistry::invoke_as`], exactly like
//!   calling the capability directly.
//! - Several providers with genuinely different parameter schemas: **one
//!   tool per provider**, named `"<name>.<provider>"` (`"block_ip.firewall"`,
//!   `"block_ip.edr"`), each targeting exactly that provider via
//!   [`crate::processing::action::ActionRegistry::invoke_provider_as`].
//!
//! # Authorization
//!
//! [`McpSurface::list_tools`] only ever returns tools `ctx.principal` is
//! allowed to see — it's built on
//! [`crate::processing::action::ActionRegistry::list_for`], not `list`.
//! [`McpSurface::call_tool`] re-checks on every call (via `invoke_as`/
//! `invoke_provider_as`), so a stale tool list can never be used to bypass a
//! permission that changed since. A [`crate::security::Decision::RequireApproval`]
//! surfaces as [`CallToolResult::is_error`] with the approval message in
//! [`CallToolResult::content`] — turning that into a real MCP elicitation
//! flow is the transport crate's job.

use crate::capability::CapabilityCatalog;
use crate::event::field::{FieldMap, FieldValue, Ip, Text, Timestamp};
use crate::event::schema::{Schema, SchemaFieldType};
use crate::processing::action::{ActionDescriptor, ActionError, AuthorizedInvocationResult};
use crate::processing::context::InvocationContext;
use crate::processing::message::TemplateRegistry;
use crate::security::Authorizer;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::LazyLock;

static PLACEHOLDER_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\{([A-Za-z0-9_.]+)\}").expect("invalid placeholder regex")
});

/// Mirrors MCP's own tool annotations
/// (`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`) —
/// see [`crate::processing::action::ActionDescriptor`]'s own hints, which
/// the first three are copied from directly. `open_world_hint` is not one
/// [`ActionDescriptor`] carries (nothing in this crate models "may this
/// touch systems outside the ones it names" more precisely than
/// "assume yes"), so it is always `true` here — a caller with better
/// information about a specific deployment can override it downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolAnnotations {
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

/// One MCP tool, derived from one or more [`ActionDescriptor`]s sharing a
/// capability name — see the module docs for the naming/fan-out rule.
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub title: String,
    pub description: String,
    pub input_schema: Value,
    pub annotations: ToolAnnotations,
}

/// One MCP resource, derived from a [`crate::capability::ComponentManifest`].
/// `uri` is always `"usiem://component/<manifest.id>"` — an ecosystem
/// convention this crate defines for its own resources, not a general MCP
/// requirement.
#[derive(Debug, Clone)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

/// One argument an [`McpPrompt`] references — best-effort, extracted from a
/// [`crate::processing::message::Template`]'s `{placeholder}` tokens (see
/// [`crate::processing::message::Template::format`]). There is no notion of
/// an optional placeholder in a `Template`, so `required` is always `true`.
#[derive(Debug, Clone)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// One MCP prompt, derived from a registered
/// [`crate::processing::message::Template`].
#[derive(Debug, Clone)]
pub struct McpPrompt {
    pub name: String,
    pub description: String,
    pub arguments: Vec<PromptArgument>,
}

/// One piece of a [`CallToolResult`]. Only plain text for now — this crate
/// has no notion of returning an image/audio/embedded-resource block, and
/// nothing here needs one yet.
#[derive(Debug, Clone)]
pub enum Content {
    Text(String),
}

/// The result of [`McpSurface::call_tool`] — MCP's own `CallToolResult`
/// shape. `structured_content` carries the same information as `content` as
/// real JSON (each provider's status/message/data), for a caller that wants
/// to parse rather than read; `content` always has at least one line so a
/// caller that only renders `content` still sees something.
#[derive(Debug, Clone)]
pub struct CallToolResult {
    pub content: Vec<Content>,
    pub structured_content: Option<Value>,
    pub is_error: bool,
}

impl CallToolResult {
    fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text(message.into())],
            structured_content: None,
            is_error: true,
        }
    }

    fn from_results(results: Vec<AuthorizedInvocationResult>) -> Self {
        let mut content = Vec::with_capacity(results.len());
        let mut entries = Vec::with_capacity(results.len());
        let mut any_success = false;

        for r in &results {
            let (status, message, data) = match &r.result {
                Ok(outcome) => {
                    if outcome.is_success() {
                        any_success = true;
                    }
                    (
                        outcome.status.as_str().to_string(),
                        outcome.message.text.clone(),
                        Some(field_map_to_json(&outcome.data)),
                    )
                }
                Err(ActionError::Unauthorized(msg)) => {
                    ("unauthorized".to_string(), msg.text.clone(), None)
                }
                Err(ActionError::ApprovalRequired(msg)) => {
                    ("approval_required".to_string(), msg.text.clone(), None)
                }
                Err(err) => ("error".to_string(), err.to_string(), None),
            };
            content.push(Content::Text(format!(
                "[{}] {status}: {message}",
                r.provider
            )));
            entries.push(json!({
                "provider": r.provider,
                "status": status,
                "message": message,
                "data": data,
            }));
        }

        if results.is_empty() {
            content.push(Content::Text(
                "no provider registered under this capability".to_string(),
            ));
        }

        Self {
            content,
            structured_content: Some(Value::Array(entries)),
            is_error: !any_success,
        }
    }
}

/// One resolved MCP tool: which `(action name, optional specific provider)`
/// it dispatches to, and the [`ActionDescriptor`] its schema/annotations are
/// drawn from. See the module docs for the naming/fan-out rule this
/// implements.
struct ResolvedTool {
    tool_name: String,
    action_name: String,
    /// `Some(provider)` to target exactly that provider via
    /// [`crate::processing::action::ActionRegistry::invoke_provider_as`];
    /// `None` to fan out to every provider under `action_name` via
    /// [`crate::processing::action::ActionRegistry::invoke_as`].
    provider: Option<String>,
    descriptor: ActionDescriptor,
}

/// Turns a [`CapabilityCatalog`], filtered through an [`Authorizer`], into
/// MCP's tool/resource/prompt vocabulary. See the module docs for the full
/// design.
pub struct McpSurface<'a> {
    catalog: &'a CapabilityCatalog,
    authz: &'a dyn Authorizer,
    templates: Option<&'a TemplateRegistry>,
}

impl<'a> McpSurface<'a> {
    pub fn new(catalog: &'a CapabilityCatalog, authz: &'a dyn Authorizer) -> Self {
        Self {
            catalog,
            authz,
            templates: None,
        }
    }

    /// Attach a [`TemplateRegistry`] so [`McpSurface::list_prompts`] has
    /// something to derive prompts from. Without one, `list_prompts` always
    /// returns an empty list.
    pub fn with_templates(mut self, templates: &'a TemplateRegistry) -> Self {
        self.templates = Some(templates);
        self
    }

    fn resolve_tools(&self, ctx: &InvocationContext) -> Vec<ResolvedTool> {
        let visible = self.catalog.actions().list_for(ctx, self.authz);

        let mut by_name: HashMap<String, Vec<ActionDescriptor>> = HashMap::new();
        for descriptor in visible {
            by_name
                .entry(descriptor.name.clone())
                .or_default()
                .push(descriptor);
        }

        let mut tools = Vec::new();
        for (name, group) in by_name {
            if group.len() == 1 {
                let descriptor = group.into_iter().next().expect("len checked above");
                tools.push(ResolvedTool {
                    tool_name: name.clone(),
                    action_name: name,
                    provider: None,
                    descriptor,
                });
                continue;
            }

            let first_schema = group[0].params.to_json_schema();
            let all_agree = group
                .iter()
                .all(|d| d.params.to_json_schema() == first_schema);

            if all_agree {
                let descriptor = group.into_iter().next().expect("checked non-empty above");
                tools.push(ResolvedTool {
                    tool_name: name.clone(),
                    action_name: name,
                    provider: None,
                    descriptor,
                });
            } else {
                for descriptor in group {
                    let tool_name = format!("{name}.{}", descriptor.provider);
                    tools.push(ResolvedTool {
                        tool_name,
                        action_name: name.clone(),
                        provider: Some(descriptor.provider.clone()),
                        descriptor,
                    });
                }
            }
        }
        tools
    }

    /// Every tool `ctx.principal` is currently allowed to see. See the
    /// module docs for naming and the "Authorization" section for why this
    /// alone is not sufficient to skip re-checking on
    /// [`McpSurface::call_tool`].
    pub fn list_tools(&self, ctx: &InvocationContext) -> Vec<McpTool> {
        self.resolve_tools(ctx)
            .into_iter()
            .map(|tool| McpTool {
                name: tool.tool_name,
                title: tool.descriptor.name.clone(),
                description: tool.descriptor.description.clone(),
                input_schema: tool.descriptor.params.to_json_schema(),
                annotations: ToolAnnotations {
                    read_only_hint: tool.descriptor.read_only,
                    destructive_hint: tool.descriptor.destructive,
                    idempotent_hint: tool.descriptor.idempotent,
                    open_world_hint: true,
                },
            })
            .collect()
    }

    /// Executes one tool call: converts `arguments` to a
    /// [`crate::event::field::FieldMap`] (type-directed by the target
    /// provider's own [`crate::event::Schema`], so e.g. `"203.0.113.5"`
    /// becomes [`FieldValue::Ip`] rather than [`FieldValue::Str`] when the
    /// schema says the field is an IP), authorizes and runs it via
    /// [`crate::processing::action::ActionRegistry::invoke_as`]/
    /// [`crate::processing::action::ActionRegistry::invoke_provider_as`],
    /// and reports the outcome.
    pub fn call_tool(
        &self,
        ctx: &InvocationContext,
        name: &str,
        arguments: &Value,
    ) -> CallToolResult {
        let tools = self.resolve_tools(ctx);
        let Some(tool) = tools.iter().find(|t| t.tool_name == name) else {
            return CallToolResult::error(format!(
                "unknown tool '{name}' (not registered, or not visible to this caller)"
            ));
        };

        let params = match json_arguments_to_field_map(&tool.descriptor.params, arguments) {
            Ok(params) => params,
            Err(message) => return CallToolResult::error(format!("invalid arguments: {message}")),
        };

        match &tool.provider {
            Some(provider) => {
                match self.catalog.actions().invoke_provider_as(
                    ctx,
                    self.authz,
                    &tool.action_name,
                    provider,
                    &params,
                ) {
                    Some(result) => CallToolResult::from_results(vec![result]),
                    None => CallToolResult::error(format!(
                        "provider '{provider}' for '{}' is no longer registered",
                        tool.action_name
                    )),
                }
            }
            None => {
                let results =
                    self.catalog
                        .actions()
                        .invoke_as(ctx, self.authz, &tool.action_name, &params);
                CallToolResult::from_results(results)
            }
        }
    }

    /// Every registered component, as an MCP resource.
    pub fn list_resources(&self) -> Vec<McpResource> {
        self.catalog
            .manifests()
            .into_iter()
            .map(|manifest| McpResource {
                uri: format!("usiem://component/{}", manifest.id),
                name: manifest.name.to_string(),
                description: manifest.description.to_string(),
                mime_type: "application/json".to_string(),
            })
            .collect()
    }

    /// Reads one `usiem://component/<id>` resource, returning its manifest
    /// as JSON. `None` for an unrecognized URI or component id.
    pub fn read_resource(&self, uri: &str) -> Option<Value> {
        let id = uri.strip_prefix("usiem://component/")?;
        let manifest = self
            .catalog
            .manifests()
            .into_iter()
            .find(|manifest| manifest.id == id)?;

        Some(json!({
            "id": manifest.id,
            "kind": manifest.kind.as_str(),
            "name": manifest.name,
            "description": manifest.description,
            "version": manifest.version,
            "datasets": manifest.datasets.iter().map(|d| json!({
                "name": d.name, "description": d.description,
            })).collect::<Vec<_>>(),
            "produces": manifest.produces.iter().map(|s| json!({
                "name": s.name, "version": s.version,
            })).collect::<Vec<_>>(),
            "permissions": manifest.permissions.iter().map(|p| json!({
                "name": p.name, "description": p.description,
            })).collect::<Vec<_>>(),
        }))
    }

    /// Every registered [`crate::processing::message::Template`] as an MCP
    /// prompt, or an empty list if no [`TemplateRegistry`] was attached via
    /// [`McpSurface::with_templates`].
    pub fn list_prompts(&self) -> Vec<McpPrompt> {
        let Some(templates) = self.templates else {
            return Vec::new();
        };
        templates
            .list()
            .into_iter()
            .filter_map(|template_id| {
                let template = templates.get(template_id)?;
                let format = template
                    .locales()
                    .next()
                    .and_then(|locale| template.format(locale))?;
                Some(McpPrompt {
                    name: template_id.to_string(),
                    description: format!("Message template '{template_id}'"),
                    arguments: extract_placeholders(format),
                })
            })
            .collect()
    }
}

/// Extracts `{placeholder}` tokens from a template format string, in first-
/// seen order with duplicates removed.
fn extract_placeholders(format: &str) -> Vec<PromptArgument> {
    let mut seen = Vec::new();
    for capture in PLACEHOLDER_REGEX.captures_iter(format) {
        let name = capture[1].to_string();
        if !seen.iter().any(|arg: &PromptArgument| arg.name == name) {
            seen.push(PromptArgument {
                description: format!("Substitution value for '{name}'"),
                name,
                required: true,
            });
        }
    }
    seen
}

/// Converts a JSON object of tool-call arguments into a [`FieldMap`],
/// type-directed by `schema` — see [`McpSurface::call_tool`]'s docs. A key
/// not declared in `schema` still converts, using
/// [`generic_json_to_field_value`]'s untyped mapping (an actual type/
/// required-field mismatch surfaces later, from the target provider calling
/// `schema.validate_field_map` itself, not from this conversion).
fn json_arguments_to_field_map(schema: &Schema, arguments: &Value) -> Result<FieldMap, String> {
    let object = match arguments {
        Value::Object(object) => object,
        Value::Null => return Ok(FieldMap::new()),
        other => return Err(format!("expected a JSON object, got {other}")),
    };

    let mut params = FieldMap::new();
    for (key, value) in object {
        let converted = match schema.fields.get(key) {
            Some(field) => json_to_field_value(value, &field.field_type)?,
            None => generic_json_to_field_value(value),
        };
        if let Some(value) = converted {
            params.insert(key.clone(), value);
        }
    }
    Ok(params)
}

/// Type-directed JSON → [`FieldValue`] conversion for one field, given its
/// declared [`SchemaFieldType`]. `Ok(None)` for a JSON `null` (treated as
/// "field not provided", not as an error or as a stored null — this crate's
/// [`FieldValue`] has no null variant).
fn json_to_field_value(value: &Value, ty: &SchemaFieldType) -> Result<Option<FieldValue>, String> {
    if value.is_null() {
        return Ok(None);
    }

    let field_value = match (value, ty) {
        (Value::String(s), SchemaFieldType::Ip) => Ip::from_str(s)
            .map(FieldValue::Ip)
            .map_err(|e| e.to_string())?,
        (Value::String(s), SchemaFieldType::Time) => Timestamp::from_rfc3339(s)
            .map(FieldValue::Time)
            .map_err(|e| e.to_string())?,
        (Value::String(s), SchemaFieldType::Str) => FieldValue::string(s.clone()),
        (Value::Bool(b), SchemaFieldType::Bool) => FieldValue::Bool(*b),
        (Value::Number(n), SchemaFieldType::Int) => FieldValue::Int(
            n.as_i64()
                .ok_or_else(|| format!("{n} is not a valid integer"))?,
        ),
        (Value::Number(n), SchemaFieldType::Uint) => FieldValue::Uint(
            n.as_u64()
                .ok_or_else(|| format!("{n} is not a valid unsigned integer"))?,
        ),
        (Value::Number(n), SchemaFieldType::Float) => FieldValue::Float(
            n.as_f64()
                .ok_or_else(|| format!("{n} is not a valid number"))?,
        ),
        (Value::Array(items), SchemaFieldType::Array(element_ty)) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                if let Some(v) = json_to_field_value(item, element_ty)? {
                    values.push(v);
                }
            }
            FieldValue::Array(values)
        }
        (Value::Object(object), SchemaFieldType::Object(nested)) => {
            let mut map = HashMap::new();
            for (key, value) in object {
                let converted = match nested.fields.get(key) {
                    Some(field) => json_to_field_value(value, &field.field_type)?,
                    None => generic_json_to_field_value(value),
                };
                if let Some(v) = converted {
                    map.insert(Text::from(key.clone()), v);
                }
            }
            FieldValue::Object(map)
        }
        (value, SchemaFieldType::Union(members)) => {
            let matched = members
                .iter()
                .find_map(|member| json_to_field_value(value, member).ok().flatten());
            match matched.or_else(|| generic_json_to_field_value(value)) {
                Some(v) => v,
                None => return Ok(None),
            }
        }
        (value, SchemaFieldType::Any) => match generic_json_to_field_value(value) {
            Some(v) => v,
            None => return Ok(None),
        },
        // Declared type didn't match the JSON shape at all — fall back to
        // an untyped conversion rather than erroring here; the target
        // provider's own `schema.validate_field_map` call (see
        // `crate::processing::action::Action::execute`'s docs) is what
        // actually surfaces a type mismatch to the caller.
        (value, _) => match generic_json_to_field_value(value) {
            Some(v) => v,
            None => return Ok(None),
        },
    };
    Ok(Some(field_value))
}

/// Untyped JSON → [`FieldValue`] conversion, used for a key with no
/// declared schema field. `None` for JSON `null`.
fn generic_json_to_field_value(value: &Value) -> Option<FieldValue> {
    match value {
        Value::Null => None,
        Value::Bool(b) => Some(FieldValue::Bool(*b)),
        Value::Number(n) => n
            .as_i64()
            .map(FieldValue::Int)
            .or_else(|| n.as_u64().map(FieldValue::Uint))
            .or_else(|| n.as_f64().map(FieldValue::Float)),
        Value::String(s) => Some(FieldValue::string(s.clone())),
        Value::Array(items) => Some(FieldValue::Array(
            items
                .iter()
                .filter_map(generic_json_to_field_value)
                .collect(),
        )),
        Value::Object(object) => Some(FieldValue::Object(
            object
                .iter()
                .filter_map(|(k, v)| {
                    generic_json_to_field_value(v).map(|v| (Text::from(k.clone()), v))
                })
                .collect(),
        )),
    }
}

/// Renders a [`FieldMap`] (e.g. an [`crate::processing::action::ActionOutcome::data`])
/// as plain JSON for [`CallToolResult::structured_content`] — the inverse
/// direction of [`json_arguments_to_field_map`], and, like
/// [`crate::event::json_schema`]'s scalar converter, deliberately not
/// [`FieldValue`]'s own tagged `Serialize` form.
fn field_map_to_json(map: &FieldMap) -> Value {
    let mut object = Map::new();
    for (key, value) in map.iter() {
        object.insert(key.to_string(), field_value_to_plain_json(value));
    }
    Value::Object(object)
}

fn field_value_to_plain_json(value: &FieldValue) -> Value {
    match value {
        FieldValue::Str(s) => json!(s.as_str()),
        FieldValue::Int(n) => json!(n),
        FieldValue::Uint(n) => json!(n),
        FieldValue::Float(n) => json!(n),
        FieldValue::Bool(b) => json!(b),
        FieldValue::Time(t) => json!(t.to_rfc3339()),
        FieldValue::Ip(ip) => json!(ip.to_string()),
        FieldValue::Bytes(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            json!(hex)
        }
        FieldValue::Object(map) => {
            let mut object = Map::new();
            for (key, value) in map {
                object.insert(key.to_string(), field_value_to_plain_json(value));
            }
            Value::Object(object)
        }
        FieldValue::Array(items) => {
            Value::Array(items.iter().map(field_value_to_plain_json).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityCatalog;
    use crate::event::field::FieldMap;
    use crate::processing::action::{Action, ActionDescriptor, ActionOutcome, ActionRegistry};
    use crate::processing::message::{LocalizedMessage, Template, TemplateRegistry};
    use crate::security::{AllowAll, Principal, PrincipalKind, RoleAuthorizer};
    use std::sync::Arc;

    struct BlockIp;
    impl Action for BlockIp {
        fn descriptor(&self) -> ActionDescriptor {
            ActionDescriptor::builder("block_ip", "firewall", "Blocks an IP at the perimeter")
                .param("ip", Schema::ip_field().required().build())
                .build()
        }

        fn execute(
            &self,
            _ctx: &InvocationContext,
            params: &FieldMap,
        ) -> Result<ActionOutcome, ActionError> {
            let ip = params.get("ip").and_then(|v| match v {
                FieldValue::Ip(ip) => Some(ip.to_string()),
                _ => None,
            });
            Ok(ActionOutcome::success(LocalizedMessage::new(
                "firewall.block_ip",
                "en-US",
                format!("blocked {}", ip.unwrap_or_default()),
            )))
        }
    }

    struct EdrIsolateIp;
    impl Action for EdrIsolateIp {
        fn descriptor(&self) -> ActionDescriptor {
            // Deliberately a *different* schema from `BlockIp` (an extra
            // required field) so the two must split into per-provider tools.
            ActionDescriptor::builder("block_ip", "edr", "Isolates an IP on all endpoints")
                .param("ip", Schema::ip_field().required().build())
                .param("reason", Schema::str_field().required().build())
                .build()
        }

        fn execute(
            &self,
            _ctx: &InvocationContext,
            _params: &FieldMap,
        ) -> Result<ActionOutcome, ActionError> {
            Ok(ActionOutcome::success(LocalizedMessage::new(
                "edr.isolate_ip",
                "en-US",
                "isolated",
            )))
        }
    }

    fn ctx_for(principal: Principal) -> InvocationContext {
        InvocationContext::new(principal)
    }

    #[test]
    fn test_single_provider_yields_one_tool_with_json_schema() {
        let mut catalog = CapabilityCatalog::new();
        catalog.actions_mut().register(Arc::new(BlockIp));
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);

        let ctx = ctx_for(Principal::new("caller", PrincipalKind::Service));
        let tools = surface.list_tools(&ctx);

        let block_ip = tools
            .iter()
            .find(|t| t.name == "block_ip")
            .expect("tool present");
        assert_eq!(block_ip.input_schema["type"], "object");
        assert_eq!(block_ip.input_schema["properties"]["ip"]["type"], "string");
        assert!(block_ip.annotations.destructive_hint);
    }

    #[test]
    fn test_disagreeing_schemas_split_into_per_provider_tools() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(BlockIp));
        registry.register(Arc::new(EdrIsolateIp));
        let mut catalog = CapabilityCatalog::new();
        *catalog.actions_mut() = registry;
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);
        let ctx = ctx_for(Principal::new("caller", PrincipalKind::Service));

        let names: Vec<String> = surface
            .list_tools(&ctx)
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert!(names.contains(&"block_ip.firewall".to_string()));
        assert!(names.contains(&"block_ip.edr".to_string()));
        assert!(!names.contains(&"block_ip".to_string()));
    }

    #[test]
    fn test_call_tool_converts_string_arg_to_ip_via_schema() {
        let mut catalog = CapabilityCatalog::new();
        catalog.actions_mut().register(Arc::new(BlockIp));
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);
        let ctx = ctx_for(Principal::new("caller", PrincipalKind::Service));

        let result = surface.call_tool(&ctx, "block_ip", &json!({"ip": "203.0.113.5"}));
        assert!(!result.is_error);
        let Content::Text(text) = &result.content[0];
        assert!(text.contains("blocked 203.0.113.5"), "got: {text}");
    }

    #[test]
    fn test_call_tool_dispatches_per_provider_tool_to_exactly_one_provider() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(BlockIp));
        registry.register(Arc::new(EdrIsolateIp));
        let mut catalog = CapabilityCatalog::new();
        *catalog.actions_mut() = registry;
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);
        let ctx = ctx_for(Principal::new("caller", PrincipalKind::Service));

        let result = surface.call_tool(
            &ctx,
            "block_ip.edr",
            &json!({"ip": "203.0.113.5", "reason": "contain"}),
        );
        assert!(!result.is_error);
        assert_eq!(
            result.structured_content.unwrap().as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn test_list_tools_hides_what_role_authorizer_denies() {
        let mut catalog = CapabilityCatalog::new();
        catalog.actions_mut().register(Arc::new(BlockIp));
        let authz = RoleAuthorizer::new().with_default_roles();
        let surface = McpSurface::new(&catalog, &authz);

        // The catalog's own built-in read_only introspection actions
        // (`siem.list_components`/`siem.component_health`) are always
        // visible to `viewer` — only `block_ip` (destructive) should be
        // hidden from it.
        let viewer_ctx = ctx_for(Principal::user("alice", ["viewer"]));
        assert!(
            !surface
                .list_tools(&viewer_ctx)
                .iter()
                .any(|t| t.name == "block_ip")
        );

        let responder_ctx = ctx_for(Principal::user("bob", ["responder"]));
        assert!(
            surface
                .list_tools(&responder_ctx)
                .iter()
                .any(|t| t.name == "block_ip")
        );
    }

    #[test]
    fn test_call_tool_on_unknown_name_is_an_error() {
        let catalog = CapabilityCatalog::new();
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);
        let ctx = ctx_for(Principal::new("caller", PrincipalKind::Service));

        let result = surface.call_tool(&ctx, "does_not_exist", &json!({}));
        assert!(result.is_error);
    }

    #[test]
    fn test_list_resources_and_read_resource_round_trip() {
        use crate::capability::{Component, ComponentKind, ComponentManifest};

        struct ToySink;
        impl Component for ToySink {
            fn manifest(&self) -> ComponentManifest {
                ComponentManifest::new("sink/toy", ComponentKind::Sink, "toy", "an in-memory sink")
            }
        }

        let mut catalog = CapabilityCatalog::new();
        catalog.register(Arc::new(ToySink));
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);

        let resources = surface.list_resources();
        let sink_resource = resources
            .iter()
            .find(|r| r.uri == "usiem://component/sink/toy")
            .expect("resource present");

        let read = surface.read_resource(&sink_resource.uri).expect("readable");
        assert_eq!(read["kind"], "sink");
        assert_eq!(read["name"], "toy");
    }

    #[test]
    fn test_list_prompts_extracts_placeholders_from_template() {
        let mut templates = TemplateRegistry::new();
        templates.register(
            Template::new("auth.brute_force_threshold")
                .with_locale("en-US", "{count} failed logins for {user} within 60s"),
        );
        let catalog = CapabilityCatalog::new();
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz).with_templates(&templates);

        let prompts = surface.list_prompts();
        assert_eq!(prompts.len(), 1);
        let arg_names: Vec<&str> = prompts[0]
            .arguments
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(arg_names, vec!["count", "user"]);
    }

    #[test]
    fn test_list_prompts_empty_without_templates_attached() {
        let catalog = CapabilityCatalog::new();
        let authz = AllowAll;
        let surface = McpSurface::new(&catalog, &authz);
        assert!(surface.list_prompts().is_empty());
    }
}
