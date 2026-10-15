//! Demonstrates `crate::capability`'s `CapabilityCatalog`: every kind of
//! component — a stateful `Component` (a toy GeoIP-ish dataset and a toy
//! sink) and stateless fn-pointer registries (`ParserRegistry`, `Pipeline`)
//! — describing itself through one uniform manifest shape, plus the
//! catalog's own built-in introspection actions.
//!
//! Run with: `cargo run --example capability_catalog`

use std::sync::Arc;
use usiem::event::field::Text;
use usiem::prelude::*;

/// A stateful `Component`: a toy in-memory GeoIP-ish dataset that also
/// self-registers a `lookup_ip` action — the "old u-siem capability
/// registration" story, without a global kernel.
struct ToyGeoIpDataset;

struct LookupIpAction;
impl Action for LookupIpAction {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "lookup_ip",
            "dataset/toy_geoip",
            "Looks up a toy geo record for an IP",
        )
        .param("ip", Schema::str_field().required().build())
        .read_only()
        .idempotent()
        .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        let ip = params.getter("ip").as_str_or("?");
        Ok(ActionOutcome::success(LocalizedMessage::new(
            "toy_geoip.lookup_ip",
            "en-US",
            format!("{ip} -> Toyland"),
        )))
    }
}

impl Component for ToyGeoIpDataset {
    fn manifest(&self) -> ComponentManifest {
        let mut manifest = ComponentManifest::new(
            "dataset/toy_geoip",
            ComponentKind::Dataset,
            "toy_geoip",
            "An in-memory placeholder GeoIP dataset",
        );
        manifest
            .datasets
            .push(DatasetDescriptor::new("toy_geoip", "IP -> toy geo record"));
        manifest
    }

    fn actions(&self) -> Vec<Arc<dyn Action>> {
        vec![Arc::new(LookupIpAction)]
    }

    fn health(&self) -> ComponentHealth {
        ComponentHealth::Healthy
    }
}

/// A second stateful `Component`, with no actions of its own — most of a
/// `Sink`'s value is in shipping events, not in exposing a capability.
struct ToyStdoutSink;

impl Component for ToyStdoutSink {
    fn manifest(&self) -> ComponentManifest {
        ComponentManifest::new(
            "sink/stdout",
            ComponentKind::Sink,
            "stdout",
            "Prints every event it receives",
        )
    }

    fn health(&self) -> ComponentHealth {
        ComponentHealth::Degraded(Text::from("stdout is slow under heavy load"))
    }
}

fn main() {
    let mut catalog = CapabilityCatalog::new();
    catalog.register(Arc::new(ToyGeoIpDataset));
    catalog.register(Arc::new(ToyStdoutSink));

    // Stateless fn-pointer stages describe themselves too, without becoming
    // `Component`s — via a plain `manifests()` method on their own registry.
    let mut parsers = ParserRegistry::new();
    parsers.register(apache_common_parser());
    let mut pipeline = Pipeline::new();
    pipeline.add_stage(Processor::new(
        "tag_internal_ip",
        "Flags events whose client.ip is in a private range",
        ProcessResult::Continue,
    ));

    println!("Registered components:");
    for manifest in catalog.manifests() {
        println!(
            "  {} [{}] — {}",
            manifest.id,
            manifest.kind.as_str(),
            manifest.description
        );
    }
    println!("\nStateless stages (still self-describing, no Component impl):");
    for manifest in parsers.manifests().into_iter().chain(pipeline.manifests()) {
        println!(
            "  {} [{}] — {}",
            manifest.id,
            manifest.kind.as_str(),
            manifest.description
        );
    }

    println!("\nHealth snapshot:");
    for (id, health) in catalog.health() {
        match health.detail() {
            Some(detail) => println!("  {id}: {} ({detail})", health.as_str()),
            None => println!("  {id}: {}", health.as_str()),
        }
    }

    // The catalog's own built-in introspection actions, plus every
    // component-provided action, are all reachable through the same
    // ActionRegistry — one interaction surface, as always.
    println!("\nEvery discoverable capability (component-provided + built-in introspection):");
    for descriptor in catalog.actions().list() {
        println!("  {} (provider={})", descriptor.name, descriptor.provider);
    }

    let ctx = InvocationContext::new(Principal::new("operator-cli", PrincipalKind::Service));
    let mut params = FieldMap::new();
    params.insert("ip", FieldValue::str("203.0.113.5"));
    for result in catalog.actions().invoke(&ctx, "lookup_ip", &params) {
        if let Ok(outcome) = result.result {
            println!("\n[lookup_ip via catalog] {}", outcome.message.text);
        }
    }
}
