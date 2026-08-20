//! Framework interface for firing a response action/command — e.g. "add
//! this IP to a blocklist", "isolate this host" — as a discoverable,
//! plug-and-play capability that any number of components can independently
//! implement.
//!
//! # Design
//!
//! Mirrors [`crate::processing::sink::Sink`]/[`crate::ingest::collector::Collector`]:
//! [`Action`] is a contract only, with no concrete implementations shipped
//! here. It deviates from those siblings in one way: `execute` takes `&self`
//! rather than `&mut self`, because the same action is expected to run
//! concurrently — fired by application code, by a `Sink`'s side effect, and
//! (via [`ActionRegistry::invoke`]) alongside every other provider of the
//! same capability at once. Any mutable state a real action needs (an HTTP
//! client, a rate limiter) is the implementor's own interior mutability, the
//! same reason `AnyDataset` in [`crate::processing::enrichment::core`] is
//! `&self`.
//!
//! # Why a registry, and why it isn't a kernel
//!
//! An earlier (non-Rust) uSIEM project had many concrete actions, each
//! self-registering into a single global "kernel" singleton at startup —
//! good for plug-and-play discovery, bad for hidden global mutable state.
//! [`ActionRegistry`] keeps the discoverability without the singleton: it's
//! a plain, `Default`-constructible struct that application code owns and
//! populates explicitly, the same relationship
//! [`crate::processing::enrichment::registry::EnrichmentRegistry`] has to
//! the datasets it holds.
//!
//! Crucially, a capability name (e.g. `"block_ip"`) maps to *many*
//! providers, not one: a firewall integration and an EDR integration can
//! both register themselves under `"block_ip"` without knowing about each
//! other, and a rule or SOAR playbook that fires `"block_ip"` reaches both
//! automatically via [`ActionRegistry::invoke`] — genuine plug-and-play,
//! with no wiring required at the call site. `invoke` fans out and hands
//! back every provider's raw result; it deliberately does not decide what
//! "succeeded overall" means across N providers — that judgment call is
//! left to whatever called it, for the same reason this crate has no
//! correlation/rule-engine API of its own.
//!
//! Capability names like `"block_ip"` are an ecosystem/application
//! convention, not something this crate defines — the same way dotted
//! `FieldValue` field names (`client.ip`, `action.*`) are a convention, not
//! an enum.
//!
//! # Not just response actions — the SIEM's one interaction surface
//!
//! `Action`/[`ActionRegistry`] is not limited to SOAR-style response
//! actions. The same shape covers admin/config commands (e.g. an action
//! wrapping [`crate::observability::set_max_level`] to change the log level,
//! or one holding a `Arc<Mutex<Pipeline>>` to reorder stages) and read-only
//! commands like "search logs" or "list registered parsers" — a query just
//! returns its result via [`ActionOutcome::data`] instead of judging an
//! external effect. This is deliberate: storage/indexing stays out of this
//! crate's scope exactly as before (no search/storage implementation is
//! shipped here either), but *if* an application wants to expose search, or
//! any other read, to the same MCP/AI-driven caller that fires response
//! actions, it registers it the same way — one capability among others in
//! the same [`ActionRegistry`]. The point is that every interaction with the
//! SIEM, not only its responses, can be discovered and invoked through this
//! one self-describing surface, so a caller (an MCP server, or an AI
//! composing a UI/CLI on the fly from what it discovers) never needs a
//! second, differently-shaped mechanism for reads versus writes.
//!
//! [`ActionDescriptor`]'s `read_only`/`destructive`/`idempotent` hints exist
//! for that caller: they mirror MCP's own `readOnlyHint`/`destructiveHint`/
//! `idempotentHint` tool annotations, so a future MCP integration can
//! forward them directly, and so a UI/CLI generated on the fly can decide
//! how to render or gate each capability (e.g. requiring confirmation before
//! firing a `destructive` one) without knowing anything about it in advance.
//!
//! # Security note
//!
//! A `destructive`-hinted action can be just as consequential when it
//! targets the SIEM's own configuration (e.g. silencing its own logging, or
//! disabling the `Sink` that would otherwise raise an alert) as when it
//! targets an external system. This crate does not gate firing on the hint
//! in any way — the same "contracts only, zero policy" stance as everything
//! else here. Deciding who may see or fire which actions (e.g. scoping which
//! `ActionRegistry`, or which filtered subset of one, an MCP integration is
//! handed) is entirely the application's responsibility.
//!
//! # Example
//!
//! ```
//! use usiem::processing::action::{
//!     Action, ActionDescriptor, ActionError, ActionOutcome, ActionRegistry,
//! };
//! use usiem::processing::message::LocalizedMessage;
//! use usiem::event::field::{FieldMap, FieldValue};
//! use std::sync::Arc;
//!
//! struct FirewallBlockIp;
//! impl Action for FirewallBlockIp {
//!     fn descriptor(&self) -> ActionDescriptor {
//!         ActionDescriptor::builder("block_ip", "firewall", "Blocks an IP at the perimeter").build()
//!     }
//!     fn execute(&self, _params: &FieldMap) -> Result<ActionOutcome, ActionError> {
//!         Ok(ActionOutcome::success(LocalizedMessage::new("firewall.block_ip", "en-US", "blocked")))
//!     }
//! }
//!
//! struct EdrBlockIp;
//! impl Action for EdrBlockIp {
//!     fn descriptor(&self) -> ActionDescriptor {
//!         ActionDescriptor::builder("block_ip", "edr", "Isolates an IP on all managed endpoints").build()
//!     }
//!     fn execute(&self, _params: &FieldMap) -> Result<ActionOutcome, ActionError> {
//!         Ok(ActionOutcome::success(LocalizedMessage::new("edr.block_ip", "en-US", "isolated")))
//!     }
//! }
//!
//! let mut registry = ActionRegistry::new();
//! registry.register(Arc::new(FirewallBlockIp));
//! registry.register(Arc::new(EdrBlockIp));
//!
//! // A rule fires the capability by name, knowing nothing about either provider.
//! let mut params = FieldMap::new();
//! params.insert("ip", FieldValue::str("203.0.113.5"));
//! let results = registry.invoke("block_ip", &params);
//!
//! assert_eq!(results.len(), 2);
//! assert!(results.iter().all(|r| matches!(&r.result, Ok(outcome) if outcome.is_success())));
//! ```

use crate::event::core::RawData;
use crate::event::field::{FieldMap, FieldValue, Text, Timestamp};
use crate::event::{CoreEvent, Origin, Schema, SchemaError, SchemaField};
use crate::processing::message::LocalizedMessage;
use std::collections::HashMap;
use std::sync::Arc;

/// Framework interface for a fireable response action.
///
/// `&self`, not `&mut self` (unlike [`crate::processing::sink::Sink`]/
/// [`crate::ingest::collector::Collector`]) — see the module docs for why.
pub trait Action: Send + Sync {
    /// Static metadata describing this action: its capability name, which
    /// provider it is, a human-readable description, and its parameter
    /// contract. Cheap enough to call for every listing (e.g. building an
    /// MCP tool list) — it does not execute anything.
    fn descriptor(&self) -> ActionDescriptor;

    /// Fire this action with the given parameters.
    ///
    /// Returns `Err` only when the action could not be attempted at all
    /// (e.g. malformed params, or the underlying integration couldn't even
    /// send a request) — implementors that want params checked up front can
    /// call `self.descriptor().params.validate_field_map(params)`
    /// themselves; it is not enforced by this trait or by
    /// [`ActionRegistry`]. A domain-level failure — the action ran but
    /// didn't succeed — is `Ok(ActionOutcome { status: ActionStatus::Failure,
    /// .. })`, not `Err`.
    fn execute(&self, params: &FieldMap) -> Result<ActionOutcome, ActionError>;
}

/// Static metadata describing one [`Action`] implementation.
///
/// `name` is the shared capability/verb a caller fires without knowing who
/// implements it (e.g. `"block_ip"`) — multiple descriptors legitimately
/// share the same `name`. `provider` identifies which concrete
/// implementation this descriptor belongs to (e.g. `"firewall"`, `"edr"`),
/// used for audit trail and for targeting one specific implementation
/// directly via [`ActionRegistry::providers`].
#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    pub name: String,
    pub provider: String,
    pub description: String,
    /// This provider's own parameter contract. Providers sharing the same
    /// `name` are not required to agree on one schema.
    pub params: Schema,
    /// This provider never modifies SIEM state or triggers an external
    /// effect (e.g. a search or introspection query). Mirrors MCP's
    /// `readOnlyHint` tool annotation.
    pub read_only: bool,
    /// Firing this provider may be high-impact or irreversible. Mirrors
    /// MCP's `destructiveHint`. Defaults to `!read_only` when not set
    /// explicitly via [`ActionDescriptorBuilder::destructive`] — the same
    /// "assume caution unless told otherwise" posture MCP itself defaults
    /// to.
    pub destructive: bool,
    /// Calling this provider twice with the same params has the same
    /// effect as calling it once. Mirrors MCP's `idempotentHint`.
    pub idempotent: bool,
}

impl ActionDescriptor {
    pub fn builder(
        name: impl Into<String>,
        provider: impl Into<String>,
        description: impl Into<String>,
    ) -> ActionDescriptorBuilder {
        ActionDescriptorBuilder::new(name, provider, description)
    }
}

/// Consuming-`self` fluent builder for [`ActionDescriptor`], mirroring
/// [`crate::event::schema::SchemaFieldBuilder`]'s style.
pub struct ActionDescriptorBuilder {
    name: String,
    provider: String,
    description: String,
    params: Schema,
    read_only: bool,
    destructive: Option<bool>,
    idempotent: bool,
}

impl ActionDescriptorBuilder {
    pub fn new(
        name: impl Into<String>,
        provider: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let name = name.into();
        Self {
            params: Schema::new(name.clone(), "1".to_string()),
            name,
            provider: provider.into(),
            description: description.into(),
            read_only: false,
            destructive: None,
            idempotent: false,
        }
    }

    /// Declare one named parameter this provider accepts.
    pub fn param(mut self, name: impl Into<String>, field: SchemaField) -> Self {
        self.params.add_field(name, field);
        self
    }

    /// Mark this provider as never modifying SIEM state or triggering an
    /// external effect. Also lowers the default of
    /// [`ActionDescriptorBuilder::destructive`] to `false` if it's not set
    /// explicitly.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Explicitly state whether firing this provider may be high-impact or
    /// irreversible, overriding the default of `!read_only`.
    pub fn destructive(mut self, destructive: bool) -> Self {
        self.destructive = Some(destructive);
        self
    }

    /// Mark this provider as safe to call twice with the same params.
    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    pub fn build(self) -> ActionDescriptor {
        ActionDescriptor {
            name: self.name,
            provider: self.provider,
            description: self.description,
            params: self.params,
            read_only: self.read_only,
            destructive: self.destructive.unwrap_or(!self.read_only),
            idempotent: self.idempotent,
        }
    }
}

/// Coarse result of firing one [`Action`] provider — analogous to
/// [`crate::processing::pipeline::ProcessResult`]'s tri-state, but
/// describing a domain outcome rather than a pipeline-stage decision.
/// `Partial` is for actions with more than one internal target (e.g.
/// "blocked on 2 of 3 firewall nodes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    Success,
    Failure,
    Partial,
}

impl ActionStatus {
    /// A lowercase string form, e.g. for use as a field value.
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionStatus::Success => "success",
            ActionStatus::Failure => "failure",
            ActionStatus::Partial => "partial",
        }
    }
}

/// The structured result of firing one [`Action`] provider.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub status: ActionStatus,
    pub message: LocalizedMessage,
    /// Anything else worth reporting (e.g. `{"blocked_hosts": [...]}`).
    pub data: FieldMap,
    pub completed_at: Timestamp,
}

impl ActionOutcome {
    pub fn success(message: LocalizedMessage) -> Self {
        Self::new(ActionStatus::Success, message)
    }

    pub fn failure(message: LocalizedMessage) -> Self {
        Self::new(ActionStatus::Failure, message)
    }

    pub fn partial(message: LocalizedMessage) -> Self {
        Self::new(ActionStatus::Partial, message)
    }

    fn new(status: ActionStatus, message: LocalizedMessage) -> Self {
        Self {
            status,
            message,
            data: FieldMap::new(),
            completed_at: Timestamp::now(),
        }
    }

    /// Attach one piece of result data; chainable.
    pub fn with_data(mut self, key: impl Into<Text>, value: impl Into<FieldValue>) -> Self {
        self.data.insert(key, value);
        self
    }

    pub fn is_success(&self) -> bool {
        matches!(self.status, ActionStatus::Success)
    }

    /// Convert this outcome into a [`CoreEvent`], so a fired action's result
    /// can flow through the same [`crate::processing::sink::Sink`] used for
    /// ordinary events. Fields are namespaced under `action.*`, mirroring
    /// [`crate::processing::signal::Signal::into_event`]; `original_time` is
    /// set to when the action completed.
    pub fn into_event(self, name: &str, provider: &str, params: &FieldMap) -> CoreEvent {
        let completed_at = self.completed_at;
        let text = self.message.text.clone();
        let mut event = CoreEvent::new(
            Timestamp::now(),
            completed_at,
            Origin::from_hostname("usiem-action"),
            RawData::from_text(text),
        );
        event.add_field("event_type".to_string(), FieldValue::str("action"));
        event.add_field(
            "action.name".to_string(),
            FieldValue::string(name.to_string()),
        );
        event.add_field(
            "action.provider".to_string(),
            FieldValue::string(provider.to_string()),
        );
        event.add_field(
            "action.status".to_string(),
            FieldValue::str(self.status.as_str()),
        );
        event.add_field("action.message".to_string(), self.message.to_field_value());
        event.add_field(
            "action.data".to_string(),
            FieldValue::Object(self.data.into_map()),
        );
        event.add_field(
            "action.params".to_string(),
            FieldValue::Object(params.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        );
        event
    }
}

/// Errors from firing an [`Action`].
#[derive(Debug)]
pub enum ActionError {
    /// `params` didn't match what this provider expects. Providers opt into
    /// this check by calling `self.descriptor().params.validate_map(params)`
    /// themselves inside `execute` — it is not enforced automatically.
    InvalidParams(Vec<SchemaError>),
    /// The action could not even be attempted (e.g. the underlying HTTP
    /// client failed to send a request) — distinct from
    /// [`ActionStatus::Failure`], which means the action *did* run and has
    /// something to report.
    ExecutionFailed(Box<dyn std::error::Error + Send + Sync>),
}

impl ActionError {
    /// Convenience constructor for [`ActionError::ExecutionFailed`].
    pub fn execution_failed(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        ActionError::ExecutionFailed(err.into())
    }
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionError::InvalidParams(errors) => {
                write!(f, "invalid action params:")?;
                for error in errors {
                    write!(f, " {error};")?;
                }
                Ok(())
            }
            ActionError::ExecutionFailed(err) => write!(f, "action execution failed: {err}"),
        }
    }
}

impl std::error::Error for ActionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ActionError::ExecutionFailed(err) => Some(err.as_ref()),
            ActionError::InvalidParams(_) => None,
        }
    }
}

/// One provider's result from a fan-out [`ActionRegistry::invoke`] call.
#[derive(Debug)]
pub struct ActionInvocationResult {
    pub provider: String,
    pub result: Result<ActionOutcome, ActionError>,
}

/// A named, runtime-discoverable registry mapping a capability name to
/// every [`Action`] that has registered itself as an implementation of it.
/// See the module docs for why this replaces the old uSIEM "kernel" without
/// being a singleton, and why a name maps to many providers.
#[derive(Default)]
pub struct ActionRegistry {
    actions: HashMap<String, Vec<Arc<dyn Action>>>,
}

impl ActionRegistry {
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Register a provider under its own [`ActionDescriptor::name`].
    /// Appends — multiple providers sharing one name is the intended
    /// plug-and-play mechanism, not a collision to guard against.
    pub fn register(&mut self, action: Arc<dyn Action>) {
        let name = action.descriptor().name.clone();
        self.actions.entry(name).or_default().push(action);
    }

    /// Every provider registered under `name`, for direct/single-target use
    /// (bypassing [`ActionRegistry::invoke`]'s fan-out).
    pub fn providers(&self, name: &str) -> Vec<Arc<dyn Action>> {
        self.actions.get(name).cloned().unwrap_or_default()
    }

    /// Every registered provider's descriptor, across all capability names —
    /// discovery for e.g. an MCP tool listing.
    pub fn list(&self) -> Vec<ActionDescriptor> {
        self.actions
            .values()
            .flatten()
            .map(|action| action.descriptor())
            .collect()
    }

    /// Fan out to every provider registered under `name`, running each and
    /// collecting its result. An empty `Vec` if nothing is registered under
    /// `name` — not an error: an unimplemented capability in a given
    /// deployment is a valid state, not a caller mistake. Summarizing the
    /// results into one verdict is left to the caller.
    pub fn invoke(&self, name: &str, params: &FieldMap) -> Vec<ActionInvocationResult> {
        self.providers(name)
            .into_iter()
            .map(|action| {
                let provider = action.descriptor().provider;
                ActionInvocationResult {
                    provider,
                    result: action.execute(params),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test double: a provider requiring an `"ip"` param, tracking how many
    /// times it was actually executed (i.e. how many times it got *past*
    /// its own param validation).
    struct CountingAction {
        name: &'static str,
        provider: &'static str,
        calls: AtomicUsize,
    }

    impl CountingAction {
        fn new(name: &'static str, provider: &'static str) -> Self {
            Self {
                name,
                provider,
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Action for CountingAction {
        fn descriptor(&self) -> ActionDescriptor {
            ActionDescriptor::builder(self.name, self.provider, "test action")
                .param("ip", Schema::str_field().required().build())
                .build()
        }

        fn execute(&self, params: &FieldMap) -> Result<ActionOutcome, ActionError> {
            self.descriptor()
                .params
                .validate_field_map(params)
                .map_err(ActionError::InvalidParams)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ActionOutcome::success(LocalizedMessage::new(
                format!("{}.block_ip", self.provider),
                "en-US",
                "ok",
            )))
        }
    }

    fn sample_params() -> FieldMap {
        let mut params = FieldMap::new();
        params.insert("ip", FieldValue::str("203.0.113.5"));
        params
    }

    #[test]
    fn test_direct_call_bypasses_the_registry() {
        let action = CountingAction::new("block_ip", "firewall");
        let outcome = action.execute(&sample_params()).unwrap();
        assert!(outcome.is_success());
        assert_eq!(action.call_count(), 1);
    }

    #[test]
    fn test_action_is_usable_as_trait_object() {
        let action: Arc<dyn Action> = Arc::new(CountingAction::new("block_ip", "firewall"));
        let outcome = action.execute(&sample_params()).unwrap();
        assert!(outcome.is_success());
    }

    #[test]
    fn test_register_appends_multiple_providers_under_one_name() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(CountingAction::new("block_ip", "firewall")));
        registry.register(Arc::new(CountingAction::new("block_ip", "edr")));

        assert_eq!(registry.providers("block_ip").len(), 2);

        let mut provider_names: Vec<_> = registry
            .list()
            .into_iter()
            .map(|descriptor| descriptor.provider)
            .collect();
        provider_names.sort();
        assert_eq!(
            provider_names,
            vec!["edr".to_string(), "firewall".to_string()]
        );
    }

    #[test]
    fn test_invoke_fans_out_to_every_registered_provider() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(CountingAction::new("block_ip", "firewall")));
        registry.register(Arc::new(CountingAction::new("block_ip", "edr")));

        let results = registry.invoke("block_ip", &sample_params());

        assert_eq!(results.len(), 2);
        let mut providers: Vec<_> = results.iter().map(|r| r.provider.clone()).collect();
        providers.sort();
        assert_eq!(providers, vec!["edr".to_string(), "firewall".to_string()]);
        assert!(
            results
                .iter()
                .all(|r| matches!(&r.result, Ok(outcome) if outcome.is_success()))
        );
    }

    #[test]
    fn test_invoke_on_unregistered_name_returns_empty_not_an_error() {
        let registry = ActionRegistry::new();
        assert!(registry.invoke("isolate_host", &sample_params()).is_empty());
    }

    #[test]
    fn test_invoke_reports_invalid_params_without_reaching_execute_logic() {
        let mut registry = ActionRegistry::new();
        let action = Arc::new(CountingAction::new("block_ip", "firewall"));
        registry.register(action.clone());

        let results = registry.invoke("block_ip", &FieldMap::new());

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0].result,
            Err(ActionError::InvalidParams(_))
        ));
        assert_eq!(action.call_count(), 0);
    }

    #[test]
    fn test_registry_invocation_and_direct_call_share_the_same_instance() {
        let mut registry = ActionRegistry::new();
        let action = Arc::new(CountingAction::new("block_ip", "firewall"));
        registry.register(action.clone());

        registry.invoke("block_ip", &sample_params());
        action.execute(&sample_params()).unwrap();

        assert_eq!(action.call_count(), 2);
    }

    #[test]
    fn test_action_outcome_into_event_carries_fields() {
        let mut params = sample_params();
        params.insert("duration_secs", FieldValue::uint(3600));

        let outcome = ActionOutcome::success(LocalizedMessage::new(
            "firewall.block_ip",
            "en-US",
            "blocked 203.0.113.5",
        ))
        .with_data("rule_id", FieldValue::str("fw-42"));

        let event = outcome.into_event("block_ip", "firewall", &params);

        assert_eq!(
            event.get_field("event_type").and_then(|f| f.as_str()),
            Some("action")
        );
        assert_eq!(
            event.get_field("action.name").and_then(|f| f.as_str()),
            Some("block_ip")
        );
        assert_eq!(
            event.get_field("action.provider").and_then(|f| f.as_str()),
            Some("firewall")
        );
        assert_eq!(
            event.get_field("action.status").and_then(|f| f.as_str()),
            Some("success")
        );
        assert!(matches!(
            event.get_field("action.message"),
            Some(FieldValue::Object(_))
        ));
        assert!(matches!(
            event.get_field("action.data"),
            Some(FieldValue::Object(_))
        ));
        assert!(matches!(
            event.get_field("action.params"),
            Some(FieldValue::Object(_))
        ));
    }

    #[test]
    fn test_destructive_defaults_to_true_unless_read_only_is_set() {
        let mutating = ActionDescriptor::builder("block_ip", "firewall", "blocks an ip").build();
        assert!(!mutating.read_only);
        assert!(mutating.destructive);

        let query = ActionDescriptor::builder("search_logs", "toy_index", "searches logs")
            .read_only()
            .build();
        assert!(query.read_only);
        assert!(!query.destructive);
    }

    #[test]
    fn test_destructive_can_be_set_explicitly() {
        let safe_mutation = ActionDescriptor::builder("touch_file", "fs", "touches a file")
            .destructive(false)
            .build();
        assert!(!safe_mutation.read_only);
        assert!(!safe_mutation.destructive);

        let idempotent_query =
            ActionDescriptor::builder("list_actions", "registry", "lists actions")
                .read_only()
                .idempotent()
                .build();
        assert!(idempotent_query.idempotent);
    }

    #[test]
    fn test_action_error_display() {
        let invalid =
            ActionError::InvalidParams(vec![SchemaError::MissingRequiredField("ip".to_string())]);
        assert!(invalid.to_string().contains("ip"));

        let failed = ActionError::execution_failed(std::io::Error::other("boom"));
        assert!(failed.to_string().contains("boom"));
    }
}
