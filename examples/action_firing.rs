//! End-to-end example of the `Action`/`ActionRegistry` primitive: two toy,
//! mutually-unaware providers both register themselves under the same
//! capability name (`"block_ip"`), and a stand-in "rule" fires that name
//! without knowing either exists — genuine plug-and-play. Also shows the
//! validation gate (an `Action` opting into schema-checked params) and the
//! direct/single-target call path alongside the fan-out one.
//!
//! Run with: `cargo run --example action_firing`

use std::sync::Arc;
use usiem::event::Event;
use usiem::prelude::*;

/// A firewall integration's own implementation of "block_ip" — knows
/// nothing about `EdrBlockIp` below.
struct FirewallBlockIp;

impl Action for FirewallBlockIp {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "block_ip",
            "firewall",
            "Blocks an IP at the network perimeter",
        )
        .param("ip", Schema::str_field().required().build())
        .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        self.descriptor()
            .params
            .validate_field_map(params)
            .map_err(ActionError::InvalidParams)?;
        let ip = params.getter("ip").as_str_or("?");
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "firewall.block_ip",
            "en-US",
            format!("blocked {ip} at the perimeter firewall"),
        )))
    }
}

/// An EDR integration's own implementation of "block_ip" — also knows
/// nothing about `FirewallBlockIp`.
struct EdrBlockIp;

impl Action for EdrBlockIp {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "block_ip",
            "edr",
            "Isolates an IP on every managed endpoint",
        )
        .param("ip", Schema::str_field().required().build())
        .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        self.descriptor()
            .params
            .validate_field_map(params)
            .map_err(ActionError::InvalidParams)?;
        let ip = params.getter("ip").as_str_or("?");
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "edr.block_ip",
            "en-US",
            format!("isolated {ip} on all managed endpoints"),
        )))
    }
}

/// A trivial output that prints events to stdout, reused to ship each
/// provider's outcome as an auditable event. A real application writes to
/// its event store instead.
struct StdoutSink;

impl StdoutSink {
    fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!(
            "[sink] {}",
            event
                .get_field("action.message")
                .map(|_| "audit event recorded")
                .unwrap_or("event")
        );
        Ok(())
    }
}

fn main() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(FirewallBlockIp));
    registry.register(Arc::new(EdrBlockIp));

    let mut sink = StdoutSink;

    // A trusted in-process caller with no external identity to check —
    // exactly what `ActionRegistry::invoke` (unauthenticated) is for. See
    // `examples/rbac.rs` for the enforced `invoke_as` path.
    let ctx = InvocationContext::new(Principal::new("rule-engine", PrincipalKind::Service));

    // --- A "rule" fires the capability by name, knowing nothing about ---
    // --- either provider: genuine plug-and-play. ---
    let mut params = FieldMap::new();
    params.insert("ip", FieldValue::str("203.0.113.5"));

    let results = registry.invoke(&ctx, "block_ip", &params);
    let succeeded = results
        .iter()
        .filter(|r| matches!(&r.result, Ok(outcome) if outcome.is_success()))
        .count();
    println!(
        "[rule] fired 'block_ip' -> succeeded on {succeeded}/{} providers",
        results.len()
    );

    // Summarizing "did it succeed overall" is the caller's job, not the
    // registry's — it just handed back each provider's raw result above.
    for result in results {
        match result.result {
            Ok(outcome) => {
                let event = outcome.into_event("block_ip", &result.provider, &params);
                sink.send(&event).unwrap();
            }
            Err(err) => eprintln!("[rule] provider '{}' failed: {err}", result.provider),
        }
    }

    // --- The validation gate: missing the required "ip" param. ---
    let bad_results = registry.invoke(&ctx, "block_ip", &FieldMap::new());
    for result in &bad_results {
        match &result.result {
            Err(ActionError::InvalidParams(errors)) => {
                println!(
                    "[rule] provider '{}' rejected empty params: {:?}",
                    result.provider, errors
                );
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    // --- Direct/single-target call: bypass the fan-out entirely. ---
    if let Some(firewall_only) = registry
        .providers("block_ip")
        .into_iter()
        .find(|action| action.descriptor().provider == "firewall")
    {
        let outcome = firewall_only.execute(&ctx, &params).unwrap();
        println!(
            "[rule] direct call to 'firewall' only: {}",
            outcome.message.text
        );
    }
}
