//! Demonstrates `crate::security`'s RBAC model applied through
//! `ActionRegistry::list_for`/`invoke_as`: an `analyst` principal and an
//! `agent_readonly`/`responder`-as-agent principal get different filtered
//! tool lists, a denied invoke is still audited, and a destructive action
//! fired by an agent principal is held for approval instead of running.
//!
//! Run with: `cargo run --example rbac`

use std::sync::Arc;
use usiem::prelude::*;

struct BlockIp;
impl Action for BlockIp {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder("block_ip", "firewall", "Blocks an IP at the perimeter")
            .param("ip", Schema::str_field().required().build())
            .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        let ip = params.getter("ip").as_str_or("?");
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "firewall.block_ip",
            "en-US",
            format!("blocked {ip}"),
        )))
    }
}

struct SearchLogs;
impl Action for SearchLogs {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder("search_logs", "toy_index", "Searches a toy log store")
            .param("query", Schema::str_field().required().build())
            .read_only()
            .idempotent()
            .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        _params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "toy_index.search_logs",
            "en-US",
            "0 matches",
        )))
    }
}

fn print_visible(
    label: &str,
    registry: &ActionRegistry,
    ctx: &InvocationContext,
    authz: &RoleAuthorizer,
) {
    let visible: Vec<String> = registry
        .list_for(ctx, authz)
        .into_iter()
        .map(|d| d.name)
        .collect();
    println!("{label} can see: {visible:?}");
}

fn main() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(BlockIp));
    registry.register(Arc::new(SearchLogs));

    let authz = RoleAuthorizer::new().with_default_roles();

    let mut params = FieldMap::new();
    params.insert("ip", FieldValue::str("203.0.113.5"));

    // --- A viewer: read-only, can see search_logs but not block_ip. ---
    let viewer_ctx = InvocationContext::new(Principal::user("alice", ["viewer"]));
    print_visible("viewer", &registry, &viewer_ctx, &authz);

    let denied = registry.invoke_as(&viewer_ctx, &authz, "block_ip", &params);
    match &denied[0].result {
        Err(ActionError::Unauthorized(msg)) => println!("viewer denied: {}", msg.text),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    println!(
        "  -> still audited: authz.decision={:?}",
        denied[0]
            .audit
            .get_field("authz.decision")
            .and_then(|f| f.as_str())
    );

    // --- A human responder: can invoke block_ip directly. ---
    let responder_ctx = InvocationContext::new(Principal::user("bob", ["responder"]))
        .with_reason("contain active intrusion");
    print_visible("responder", &registry, &responder_ctx, &authz);
    let allowed = registry.invoke_as(&responder_ctx, &authz, "block_ip", &params);
    match &allowed[0].result {
        Ok(outcome) => println!("responder invoked: {}", outcome.message.text),
        other => panic!("expected Ok, got {other:?}"),
    }

    // --- The same `responder` role, but the caller is an AI/MCP agent: ---
    // --- destructive + agent => held for approval, not run. ---
    let agent_ctx = InvocationContext::new(Principal::agent("copilot", ["responder"]));
    let held = registry.invoke_as(&agent_ctx, &authz, "block_ip", &params);
    match &held[0].result {
        Err(ActionError::ApprovalRequired(msg)) => {
            println!("agent held for approval: {}", msg.text)
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }

    // --- An agent restricted to read-only capabilities never even sees ---
    // --- block_ip, and search_logs runs without needing approval. ---
    let agent_readonly_ctx =
        InvocationContext::new(Principal::agent("readonly-bot", ["agent_readonly"]));
    print_visible("agent_readonly", &registry, &agent_readonly_ctx, &authz);
    let mut query = FieldMap::new();
    query.insert("query", FieldValue::str("failed login"));
    let search = registry.invoke_as(&agent_readonly_ctx, &authz, "search_logs", &query);
    match &search[0].result {
        Ok(outcome) => println!("agent_readonly searched: {}", outcome.message.text),
        other => panic!("expected Ok, got {other:?}"),
    }
}
