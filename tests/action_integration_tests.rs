//! End-to-end test wiring `Action`/`ActionRegistry` into a `Sink`.
//!
//! Proves the core requirement behind the primitive: a rule (or, here, a
//! `Sink`'s own side effect) fires a capability by name, knowing nothing
//! about who implements it, and every independently-registered provider
//! runs — with the same registry also reachable directly from application
//! code, outside of any `Sink::send` call.

use std::sync::{Arc, Mutex};

use usiem::event::CoreEvent as Event;
use usiem::event::field::{FieldMap, FieldValue, Timestamp};
use usiem::event::{Origin, RawData};
use usiem::processing::action::{
    Action, ActionDescriptor, ActionError, ActionOutcome, ActionRegistry,
};
use usiem::processing::context::InvocationContext;
use usiem::processing::message::LocalizedMessage;
use usiem::processing::sink::Sink;
use usiem::security::{Principal, PrincipalKind};

fn system_ctx() -> InvocationContext {
    InvocationContext::new(Principal::new("system", PrincipalKind::Service))
}

/// A toy provider standing in for one component's implementation of a
/// shared capability. Mutually unaware of any other provider registered
/// under the same name.
struct ToyProvider {
    name: &'static str,
    provider: &'static str,
}

impl Action for ToyProvider {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            self.name,
            self.provider,
            "toy provider for integration testing",
        )
        .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError> {
        let ip = params.getter("ip").as_str_or("<unknown>");
        Ok(ActionOutcome::success(LocalizedMessage::new(
            format!("{}.block_ip", self.provider),
            "en-US",
            format!("{} blocked {ip}", self.provider),
        )))
    }
}

/// A `Sink` test double that fires a capability as a side effect of
/// receiving an event, then records every event it was asked to send —
/// including the audit events produced from the fired action's outcomes.
struct RecordingSink {
    actions: Arc<ActionRegistry>,
    sent: Mutex<Vec<String>>,
}

impl Sink for RecordingSink {
    fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sent.lock().unwrap().push(event.raw_data().as_string());

        if let Some(ip) = event.get_field("client.ip").and_then(|f| f.as_str()) {
            let mut params = FieldMap::new();
            params.insert("ip", FieldValue::string(ip.to_string()));

            for result in self.actions.invoke(&system_ctx(), "block_ip", &params) {
                if let Ok(outcome) = result.result {
                    let audit_event = outcome.into_event("block_ip", &result.provider, &params);
                    self.sent
                        .lock()
                        .unwrap()
                        .push(audit_event.raw_data().as_string());
                }
            }
        }
        Ok(())
    }
}

fn sample_event(ip: &str) -> Event {
    let mut event = Event::new(
        Timestamp::now(),
        Timestamp::now(),
        Origin::from_hostname("test-host"),
        RawData::from_text("suspicious connection"),
    );
    event.add_field("client.ip", FieldValue::string(ip.to_string()));
    event
}

#[test]
fn test_sink_fires_action_reaching_every_registered_provider() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ToyProvider {
        name: "block_ip",
        provider: "firewall",
    }));
    registry.register(Arc::new(ToyProvider {
        name: "block_ip",
        provider: "edr",
    }));
    let actions = Arc::new(registry);

    let mut sink = RecordingSink {
        actions: actions.clone(),
        sent: Mutex::new(Vec::new()),
    };

    sink.send(&sample_event("203.0.113.5")).unwrap();

    let sent = sink.sent.lock().unwrap();
    // The original event, plus one audit event per registered provider —
    // the Sink never named "firewall" or "edr" anywhere in its own code.
    assert_eq!(sent.len(), 3);
    assert!(sent.iter().any(|text| text.contains("firewall blocked")));
    assert!(sent.iter().any(|text| text.contains("edr blocked")));
}

#[test]
fn test_direct_invoke_reaches_the_same_providers_outside_any_sink() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ToyProvider {
        name: "block_ip",
        provider: "firewall",
    }));
    registry.register(Arc::new(ToyProvider {
        name: "block_ip",
        provider: "edr",
    }));

    let mut params = FieldMap::new();
    params.insert("ip", FieldValue::str("198.51.100.9"));

    let results = registry.invoke(&system_ctx(), "block_ip", &params);

    assert_eq!(results.len(), 2);
    let mut providers: Vec<_> = results.iter().map(|r| r.provider.clone()).collect();
    providers.sort();
    assert_eq!(providers, vec!["edr".to_string(), "firewall".to_string()]);
}
