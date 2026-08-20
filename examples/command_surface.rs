//! Demonstrates that `Action`/`ActionRegistry` is one interaction surface
//! for the whole SIEM, not just SOAR-style response actions: a response
//! action, an admin/config command, and a read-only search command all
//! register into the same `ActionRegistry` side by side. The key beat is
//! calling `registry.list()` at the end and printing each descriptor's
//! `read_only`/`destructive`/`idempotent` hints — a caller that has never
//! seen this codebase can discover and correctly reason about every
//! capability from that alone, which is what lets an MCP server (or an AI
//! composing a UI/CLI on the fly) drive the SIEM without a bespoke
//! frontend.
//!
//! For the full SOAR fan-out story (multiple independent providers under
//! one capability name), see `examples/action_firing.rs`.
//!
//! Run with: `cargo run --example command_surface`

use std::collections::HashMap;
use std::sync::Arc;
use usiem::event::field::Text;
use usiem::observability::{Level, max_level, set_max_level};
use usiem::prelude::*;

/// A response action: fires an external effect. Mutating, not read-only —
/// `destructive` defaults to `true`.
struct BlockIp;

impl Action for BlockIp {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder("block_ip", "firewall", "Blocks an IP at the perimeter")
            .param("ip", Schema::str_field().required().build())
            .build()
    }

    fn execute(&self, params: &FieldMap) -> Result<ActionOutcome, ActionError> {
        self.descriptor()
            .params
            .validate_field_map(params)
            .map_err(ActionError::InvalidParams)?;
        let ip = params.getter("ip").as_str_or("?");
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "firewall.block_ip",
            "en-US",
            format!("blocked {ip}"),
        )))
    }
}

/// An admin/config action: reaches into the SIEM's own observability
/// facade via `usiem::observability::set_max_level`. Explicitly marked
/// `destructive` — silencing the SIEM's own logging is exactly the
/// high-impact case that hint exists to flag.
struct SetLogLevelAction;

impl Action for SetLogLevelAction {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "set_log_level",
            "observability",
            "Changes the SIEM's own internal log verbosity",
        )
        .param(
            "level",
            Schema::str_field()
                .required()
                .allowed_values(["error", "warn", "info", "debug", "trace"])
                .build(),
        )
        .destructive(true)
        .build()
    }

    fn execute(&self, params: &FieldMap) -> Result<ActionOutcome, ActionError> {
        self.descriptor()
            .params
            .validate_field_map(params)
            .map_err(ActionError::InvalidParams)?;
        let level = match params.getter("level").as_str() {
            Some("error") => Level::Error,
            Some("warn") => Level::Warn,
            Some("info") => Level::Info,
            Some("debug") => Level::Debug,
            Some("trace") => Level::Trace,
            _ => unreachable!("validated against allowed_values above"),
        };
        let previous = max_level();
        set_max_level(level);
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "observability.set_log_level",
            "en-US",
            format!("log level changed from {previous:?} to {level:?}"),
        )))
    }
}

/// A read-only search action over a small in-memory toy dataset — no real
/// search/storage implementation, same zero-bundled-impl policy as every
/// other extension point. `read_only` and `idempotent`; `destructive`
/// defaults to `false` because of `read_only`.
struct ToySearchAction {
    log_lines: Vec<&'static str>,
}

impl Action for ToySearchAction {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "search_logs",
            "toy_index",
            "Searches a toy in-memory log store",
        )
        .param("query", Schema::str_field().required().build())
        .read_only()
        .idempotent()
        .build()
    }

    fn execute(&self, params: &FieldMap) -> Result<ActionOutcome, ActionError> {
        self.descriptor()
            .params
            .validate_field_map(params)
            .map_err(ActionError::InvalidParams)?;
        let query = params.getter("query").as_str_or("");

        let matches: Vec<FieldValue> = self
            .log_lines
            .iter()
            .filter(|line| line.contains(query))
            .map(|line| {
                let mut object = HashMap::new();
                object.insert(Text::from("text"), FieldValue::str(line));
                FieldValue::Object(object)
            })
            .collect();

        Ok(ActionOutcome::success(LocalizedMessage::new(
            "toy_index.search_logs",
            "en-US",
            format!("{} match(es) for {query:?}", matches.len()),
        ))
        .with_data("matches", FieldValue::Array(matches)))
    }
}

fn main() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(BlockIp));
    registry.register(Arc::new(SetLogLevelAction));
    registry.register(Arc::new(ToySearchAction {
        log_lines: vec![
            "203.0.113.5 failed login for alice",
            "203.0.113.5 failed login for alice",
            "198.51.100.9 successful login for bob",
        ],
    }));

    // The self-description a caller who has never seen this codebase would
    // see — enough to know what each capability is, what it expects, and
    // how carefully to treat it, with no bespoke frontend involved.
    println!("Discoverable capabilities:");
    for descriptor in registry.list() {
        println!(
            "  {} (provider={}) read_only={} destructive={} idempotent={}",
            descriptor.name,
            descriptor.provider,
            descriptor.read_only,
            descriptor.destructive,
            descriptor.idempotent
        );
    }

    println!("\nFiring 'search_logs' (read-only, safe to call speculatively):");
    let mut search_params = FieldMap::new();
    search_params.insert("query", FieldValue::str("failed login"));
    for result in registry.invoke("search_logs", &search_params) {
        if let Ok(outcome) = result.result {
            println!("  [{}] {}", result.provider, outcome.message.text);
        }
    }

    println!("\nFiring 'set_log_level' (destructive: changes the SIEM's own behavior):");
    let mut level_params = FieldMap::new();
    level_params.insert("level", FieldValue::str("debug"));
    for result in registry.invoke("set_log_level", &level_params) {
        match result.result {
            Ok(outcome) => println!("  [{}] {}", result.provider, outcome.message.text),
            Err(err) => eprintln!("  [{}] failed: {err}", result.provider),
        }
    }

    println!("\nFiring 'block_ip' (destructive: an external response action):");
    let mut block_params = FieldMap::new();
    block_params.insert("ip", FieldValue::str("203.0.113.5"));
    for result in registry.invoke("block_ip", &block_params) {
        if let Ok(outcome) = result.result {
            println!("  [{}] {}", result.provider, outcome.message.text);
        }
    }
}
