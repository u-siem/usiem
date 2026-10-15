//! Demonstrates `crate::mcp`'s `McpSurface`: a `CapabilityCatalog` filtered
//! through a `RoleAuthorizer` turns into an MCP tool list (with real JSON
//! Schema `inputSchema`s and read_only/destructive/idempotent annotations),
//! a resource list (one per registered component), and prompts (from a
//! `TemplateRegistry`) — with no transport, JSON-RPC framing, or network
//! code involved anywhere in this crate.
//!
//! Run with: `cargo run --example mcp_surface --features mcp`

use std::sync::Arc;
use usiem::capability::{
    CapabilityCatalog, Component, ComponentHealth, ComponentKind, ComponentManifest,
};
use usiem::event::field::FieldMap;
use usiem::event::schema::Schema;
use usiem::mcp::McpSurface;
use usiem::processing::action::{Action, ActionDescriptor, ActionError, ActionOutcome};
use usiem::processing::context::InvocationContext;
use usiem::processing::message::{LocalizedMessage, Template, TemplateRegistry};
use usiem::security::{Principal, RoleAuthorizer};

struct BlockIp;
impl Action for BlockIp {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder("block_ip", "firewall", "Blocks an IP at the perimeter")
            .param(
                "ip",
                Schema::ip_field()
                    .required()
                    .description("the IP to block")
                    .build(),
            )
            .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        let ip = params
            .get("ip")
            .map(|v| format!("{v:?}"))
            .unwrap_or_default();
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "firewall.block_ip",
            "en-US",
            format!("blocked {ip}"),
        )))
    }
}

struct ToySink;
impl Component for ToySink {
    fn manifest(&self) -> ComponentManifest {
        ComponentManifest::new(
            "sink/toy",
            ComponentKind::Sink,
            "toy",
            "An in-memory placeholder sink",
        )
    }

    fn health(&self) -> ComponentHealth {
        ComponentHealth::Healthy
    }
}

fn main() {
    let mut catalog = CapabilityCatalog::new();
    catalog.actions_mut().register(Arc::new(BlockIp));
    catalog.register(Arc::new(ToySink));

    let mut templates = TemplateRegistry::new();
    templates.register(
        Template::new("auth.brute_force_threshold")
            .with_locale("en-US", "{count} failed logins for {user} within 60s"),
    );

    let authz = RoleAuthorizer::new().with_default_roles();
    let surface = McpSurface::new(&catalog, &authz).with_templates(&templates);

    // --- What an agent (an AI/MCP-driven caller) restricted to responder ---
    // --- privileges is offered as MCP tools. ---
    let agent_ctx = InvocationContext::new(Principal::agent("copilot", ["responder"]));
    println!("MCP tools visible to an agent with the 'responder' role:");
    for tool in surface.list_tools(&agent_ctx) {
        println!(
            "  {} (read_only={} destructive={} idempotent={})",
            tool.name,
            tool.annotations.read_only_hint,
            tool.annotations.destructive_hint,
            tool.annotations.idempotent_hint,
        );
        println!("    inputSchema: {}", tool.input_schema);
    }

    println!("\nMCP resources (one per registered component):");
    for resource in surface.list_resources() {
        println!("  {} — {}", resource.uri, resource.description);
    }

    println!("\nMCP prompts (derived from the TemplateRegistry):");
    for prompt in surface.list_prompts() {
        let args: Vec<&str> = prompt.arguments.iter().map(|a| a.name.as_str()).collect();
        println!("  {} (arguments: {args:?})", prompt.name);
    }

    // --- Calling `block_ip` as an agent: destructive, so it's held for ---
    // --- approval rather than actually running. ---
    let held = surface.call_tool(
        &agent_ctx,
        "block_ip",
        &serde_json::json!({"ip": "203.0.113.5"}),
    );
    println!(
        "\nAgent calls 'block_ip' -> is_error={} content={:?}",
        held.is_error, held.content
    );

    // --- The same tool, called by a human responder: it actually runs, ---
    // --- and the JSON string argument became a real FieldValue::Ip via ---
    // --- the schema-directed conversion. ---
    let human_ctx = InvocationContext::new(Principal::user("bob", ["responder"]));
    let ran = surface.call_tool(
        &human_ctx,
        "block_ip",
        &serde_json::json!({"ip": "203.0.113.5"}),
    );
    println!(
        "Human responder calls 'block_ip' -> is_error={} content={:?}",
        ran.is_error, ran.content
    );

    // --- Reading a resource: the toy sink's manifest as JSON. ---
    if let Some(resource) = surface
        .list_resources()
        .into_iter()
        .find(|r| r.uri.contains("sink/toy"))
    {
        let body = surface.read_resource(&resource.uri).unwrap();
        println!("\nRead resource {}: {body}", resource.uri);
    }
}
