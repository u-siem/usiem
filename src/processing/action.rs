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
//! targets an external system. [`Action::execute`] itself still gates
//! nothing on the hint — the same "contracts only, zero policy" stance as
//! everything else here — but [`ActionRegistry`] now offers a second,
//! enforced path: [`ActionRegistry::list_for`]/[`ActionRegistry::invoke_as`]
//! consult a [`crate::security::Authorizer`] (this crate ships
//! [`crate::security::RoleAuthorizer`] as a bundled static-RBAC mechanism)
//! before a caller ever sees or fires a capability, and
//! [`ActionRegistry::invoke_as`] unconditionally produces an audit
//! [`crate::event::CoreEvent`] for every attempt — allowed, denied, or
//! held for approval — via [`AuthorizedInvocationResult::audit`].
//! [`ActionRegistry::list`]/[`ActionRegistry::invoke`] remain exactly as
//! before: unauthenticated, for trusted in-process code with no
//! [`crate::processing::context::InvocationContext`] to check. Any surface
//! handed to a less-trusted caller (an MCP server, a web UI) should use the
//! `_for`/`_as` methods instead — this crate cannot make that choice for the
//! application. See [`crate::security`] for the full authorization model.
//!
//! # Example
//!
//! ```
//! use usiem::processing::action::{
//!     Action, ActionDescriptor, ActionError, ActionOutcome, ActionRegistry,
//! };
//! use usiem::processing::context::InvocationContext;
//! use usiem::processing::message::LocalizedMessage;
//! use usiem::event::field::{FieldMap, FieldValue};
//! use usiem::security::{Principal, PrincipalKind};
//! use std::sync::Arc;
//!
//! struct FirewallBlockIp;
//! impl Action for FirewallBlockIp {
//!     fn descriptor(&self) -> ActionDescriptor {
//!         ActionDescriptor::builder("block_ip", "firewall", "Blocks an IP at the perimeter").build()
//!     }
//!     fn execute(&self, _ctx: &InvocationContext, _params: &FieldMap) -> Result<ActionOutcome, ActionError> {
//!         Ok(ActionOutcome::success(LocalizedMessage::new("firewall.block_ip", "en-US", "blocked")))
//!     }
//! }
//!
//! struct EdrBlockIp;
//! impl Action for EdrBlockIp {
//!     fn descriptor(&self) -> ActionDescriptor {
//!         ActionDescriptor::builder("block_ip", "edr", "Isolates an IP on all managed endpoints").build()
//!     }
//!     fn execute(&self, _ctx: &InvocationContext, _params: &FieldMap) -> Result<ActionOutcome, ActionError> {
//!         Ok(ActionOutcome::success(LocalizedMessage::new("edr.block_ip", "en-US", "isolated")))
//!     }
//! }
//!
//! let mut registry = ActionRegistry::new();
//! registry.register(Arc::new(FirewallBlockIp));
//! registry.register(Arc::new(EdrBlockIp));
//!
//! // A rule fires the capability by name, knowing nothing about either provider.
//! let ctx = InvocationContext::new(Principal::new("system", PrincipalKind::Service));
//! let mut params = FieldMap::new();
//! params.insert("ip", FieldValue::str("203.0.113.5"));
//! let results = registry.invoke(&ctx, "block_ip", &params);
//!
//! assert_eq!(results.len(), 2);
//! assert!(results.iter().all(|r| matches!(&r.result, Ok(outcome) if outcome.is_success())));
//! ```

use crate::event::core::RawData;
use crate::event::field::{FieldMap, FieldValue, Text, Timestamp};
use crate::event::{CoreEvent, Origin, Schema, SchemaError, SchemaField};
use crate::processing::context::InvocationContext;
use crate::processing::message::LocalizedMessage;
use crate::security::{Authorizer, AuthzRequest, Decision};
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
    /// `ctx` identifies the caller and carries request-scoped metadata
    /// (tenant, cancellation, audit reason) — see
    /// [`crate::processing::context::InvocationContext`]. It is *not* a
    /// promise that authorization already happened: only
    /// [`ActionRegistry::invoke_as`] enforces that, via a
    /// [`crate::security::Authorizer`]; an implementor that wants its own
    /// additional checks can still inspect `ctx.principal` here.
    ///
    /// Returns `Err` only when the action could not be attempted at all
    /// (e.g. malformed params, or the underlying integration couldn't even
    /// send a request) — implementors that want params checked up front can
    /// call `self.descriptor().params.validate_field_map(params)`
    /// themselves; it is not enforced by this trait or by
    /// [`ActionRegistry`]. A domain-level failure — the action ran but
    /// didn't succeed — is `Ok(ActionOutcome { status: ActionStatus::Failure,
    /// .. })`, not `Err`.
    fn execute(
        &self,
        ctx: &InvocationContext,
        params: &FieldMap,
    ) -> Result<ActionOutcome, ActionError>;
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
    /// The [`crate::security::Permission`] a caller must hold to invoke
    /// this provider through [`ActionRegistry::invoke_as`]/
    /// [`ActionRegistry::list_for`]. Defaults to `"action.invoke:<name>"`
    /// (see [`ActionDescriptor::required_permission`]) when not set
    /// explicitly via [`ActionDescriptorBuilder::permission`].
    pub permission: Option<String>,
}

impl ActionDescriptor {
    pub fn builder(
        name: impl Into<String>,
        provider: impl Into<String>,
        description: impl Into<String>,
    ) -> ActionDescriptorBuilder {
        ActionDescriptorBuilder::new(name, provider, description)
    }

    /// The permission string a caller must hold to invoke this provider —
    /// [`ActionDescriptor::permission`] if set explicitly, otherwise the
    /// convention `"action.invoke:<name>"`.
    pub fn required_permission(&self) -> String {
        self.permission
            .clone()
            .unwrap_or_else(|| format!("action.invoke:{}", self.name))
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
    permission: Option<String>,
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
            permission: None,
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

    /// Override the [`crate::security::Permission`] required to invoke this
    /// provider, instead of the `"action.invoke:<name>"` default.
    pub fn permission(mut self, permission: impl Into<String>) -> Self {
        self.permission = Some(permission.into());
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
            permission: self.permission,
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
        event.add_field("event_type", FieldValue::str("action"));
        event.add_field("action.name", FieldValue::string(name.to_string()));
        event.add_field("action.provider", FieldValue::string(provider.to_string()));
        event.add_field("action.status", FieldValue::str(self.status.as_str()));
        event.add_field("action.message", self.message.to_field_value());
        event.add_field("action.data", FieldValue::Object(self.data.into_map()));
        event.add_field(
            "action.params",
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
    /// [`ActionRegistry::invoke_as`] only: the caller's
    /// [`crate::security::Authorizer`] returned
    /// [`crate::security::Decision::Deny`]. `execute` was never called.
    Unauthorized(LocalizedMessage),
    /// [`ActionRegistry::invoke_as`] only: the caller's
    /// [`crate::security::Authorizer`] returned
    /// [`crate::security::Decision::RequireApproval`] — the underlying
    /// grant exists, but this call is high-impact enough to need a human to
    /// confirm it first. `execute` was never called.
    ApprovalRequired(LocalizedMessage),
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
            ActionError::Unauthorized(msg) => write!(f, "unauthorized: {}", msg.text),
            ActionError::ApprovalRequired(msg) => write!(f, "approval required: {}", msg.text),
        }
    }
}

impl std::error::Error for ActionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ActionError::ExecutionFailed(err) => Some(err.as_ref()),
            ActionError::InvalidParams(_)
            | ActionError::Unauthorized(_)
            | ActionError::ApprovalRequired(_) => None,
        }
    }
}

/// One provider's result from a fan-out [`ActionRegistry::invoke`] call.
#[derive(Debug)]
pub struct ActionInvocationResult {
    pub provider: String,
    pub result: Result<ActionOutcome, ActionError>,
}

/// One provider's result from a fan-out [`ActionRegistry::invoke_as`] call —
/// like [`ActionInvocationResult`], plus the audit [`CoreEvent`] that was
/// unconditionally produced for this attempt (see the module's "Security
/// note"). `result` is `Err(ActionError::Unauthorized(_))` or
/// `Err(ActionError::ApprovalRequired(_))` when the
/// [`crate::security::Authorizer`] didn't allow the call outright — in both
/// cases the provider's `execute` was never called.
#[derive(Debug)]
pub struct AuthorizedInvocationResult {
    pub provider: String,
    pub result: Result<ActionOutcome, ActionError>,
    pub audit: CoreEvent,
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
    ///
    /// Unauthenticated: no [`crate::security::Authorizer`] is consulted.
    /// `ctx` is passed straight through to each provider's `execute` for its
    /// own use (tenant scoping, audit context) — use
    /// [`ActionRegistry::invoke_as`] instead when the caller is untrusted.
    pub fn invoke(
        &self,
        ctx: &InvocationContext,
        name: &str,
        params: &FieldMap,
    ) -> Vec<ActionInvocationResult> {
        self.providers(name)
            .into_iter()
            .map(|action| {
                let provider = action.descriptor().provider;
                ActionInvocationResult {
                    provider,
                    result: action.execute(ctx, params),
                }
            })
            .collect()
    }

    /// Every registered provider's descriptor that `ctx.principal` is
    /// allowed to invoke per `authz` — [`crate::security::Decision::Deny`]
    /// hides a descriptor entirely;
    /// [`crate::security::Decision::RequireApproval`] still lists it (the
    /// caller may see the capability exists, just not fire it without
    /// approval). This is the discovery half of the enforced path — see
    /// [`ActionRegistry::invoke_as`] for the invocation half, and the
    /// module's "Security note" for why both exist alongside
    /// [`ActionRegistry::list`]/[`ActionRegistry::invoke`].
    pub fn list_for(
        &self,
        ctx: &InvocationContext,
        authz: &dyn Authorizer,
    ) -> Vec<ActionDescriptor> {
        self.list()
            .into_iter()
            .filter(|descriptor| {
                let permission = descriptor.required_permission();
                let request = AuthzRequest {
                    permission: &permission,
                    read_only: descriptor.read_only,
                    destructive: descriptor.destructive,
                    idempotent: descriptor.idempotent,
                };
                !matches!(authz.authorize(ctx, &request), Decision::Deny(_))
            })
            .collect()
    }

    /// Fan out to every provider registered under `name`, checking `ctx`
    /// against `authz` before calling each one and unconditionally
    /// producing an audit [`CoreEvent`] for the attempt — see
    /// [`AuthorizedInvocationResult`] and the module's "Security note".
    pub fn invoke_as(
        &self,
        ctx: &InvocationContext,
        authz: &dyn Authorizer,
        name: &str,
        params: &FieldMap,
    ) -> Vec<AuthorizedInvocationResult> {
        self.providers(name)
            .into_iter()
            .map(|action| Self::invoke_one_as(action.as_ref(), ctx, authz, params))
            .collect()
    }

    /// Like [`ActionRegistry::invoke_as`], but targets exactly one provider
    /// registered under `name` — the one whose
    /// [`ActionDescriptor::provider`] equals `provider` — instead of fanning
    /// out to all of them. `None` if no such `(name, provider)` pair is
    /// registered. Useful for a caller (e.g. an MCP surface) that has
    /// already disambiguated which specific provider it wants to invoke.
    pub fn invoke_provider_as(
        &self,
        ctx: &InvocationContext,
        authz: &dyn Authorizer,
        name: &str,
        provider: &str,
        params: &FieldMap,
    ) -> Option<AuthorizedInvocationResult> {
        let action = self
            .providers(name)
            .into_iter()
            .find(|action| action.descriptor().provider == provider)?;
        Some(Self::invoke_one_as(action.as_ref(), ctx, authz, params))
    }

    /// Shared authorize-then-execute-then-audit logic behind
    /// [`ActionRegistry::invoke_as`]/[`ActionRegistry::invoke_provider_as`].
    fn invoke_one_as(
        action: &dyn Action,
        ctx: &InvocationContext,
        authz: &dyn Authorizer,
        params: &FieldMap,
    ) -> AuthorizedInvocationResult {
        let descriptor = action.descriptor();
        let permission = descriptor.required_permission();
        let request = AuthzRequest {
            permission: &permission,
            read_only: descriptor.read_only,
            destructive: descriptor.destructive,
            idempotent: descriptor.idempotent,
        };
        let decision = authz.authorize(ctx, &request);
        let result = match &decision {
            Decision::Allow => action.execute(ctx, params),
            Decision::Deny(msg) => Err(ActionError::Unauthorized(msg.clone())),
            Decision::RequireApproval(msg) => Err(ActionError::ApprovalRequired(msg.clone())),
        };
        let audit = Self::audit_event(&descriptor, ctx, &decision, &result, params);
        AuthorizedInvocationResult {
            provider: descriptor.provider,
            result,
            audit,
        }
    }

    /// Builds the mandatory audit [`CoreEvent`] for one [`ActionRegistry::invoke_as`]
    /// attempt, regardless of its outcome. Fields are namespaced under
    /// `action.*`/`principal.*`/`authz.*`/`tenant.*`/`request.*`, mirroring
    /// [`ActionOutcome::into_event`]'s `action.*` convention.
    fn audit_event(
        descriptor: &ActionDescriptor,
        ctx: &InvocationContext,
        decision: &Decision,
        result: &Result<ActionOutcome, ActionError>,
        params: &FieldMap,
    ) -> CoreEvent {
        let now = Timestamp::now();
        let mut event = CoreEvent::new(
            now,
            now,
            Origin::from_hostname("usiem-action"),
            RawData::from_text(format!(
                "{} invocation by {}",
                descriptor.name, ctx.principal.id
            )),
        );
        event.add_field("event_type", FieldValue::str("action_audit"));
        event.add_field("action.name", FieldValue::string(descriptor.name.clone()));
        event.add_field(
            "action.provider",
            FieldValue::string(descriptor.provider.clone()),
        );
        event.add_field(
            "principal.id",
            FieldValue::string(ctx.principal.id.to_string()),
        );
        event.add_field(
            "principal.kind",
            FieldValue::string(format!("{:?}", ctx.principal.kind).to_lowercase()),
        );
        event.add_field("request.id", FieldValue::string(ctx.request_id.to_string()));
        if let Some(tenant) = &ctx.tenant {
            event.add_field("tenant.id", FieldValue::string(tenant.to_string()));
        }
        if let Some(reason) = &ctx.reason {
            event.add_field("action.reason", FieldValue::string(reason.to_string()));
        }
        let decision_str = match decision {
            Decision::Allow => "allow",
            Decision::Deny(_) => "deny",
            Decision::RequireApproval(_) => "require_approval",
        };
        event.add_field("authz.decision", FieldValue::str(decision_str));
        event.add_field(
            "action.params",
            FieldValue::Object(params.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        );
        match result {
            Ok(outcome) => {
                event.add_field("action.status", FieldValue::str(outcome.status.as_str()));
            }
            Err(err) => {
                event.add_field("action.status", FieldValue::str("error"));
                event.add_field("action.error", FieldValue::string(err.to_string()));
            }
        }
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Principal, PrincipalKind, RoleAuthorizer};
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

        fn execute(
            &self,
            _ctx: &InvocationContext,
            params: &FieldMap,
        ) -> Result<ActionOutcome, ActionError> {
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

    fn system_ctx() -> InvocationContext {
        InvocationContext::new(Principal::new("system", PrincipalKind::Service))
    }

    #[test]
    fn test_direct_call_bypasses_the_registry() {
        let action = CountingAction::new("block_ip", "firewall");
        let outcome = action.execute(&system_ctx(), &sample_params()).unwrap();
        assert!(outcome.is_success());
        assert_eq!(action.call_count(), 1);
    }

    #[test]
    fn test_action_is_usable_as_trait_object() {
        let action: Arc<dyn Action> = Arc::new(CountingAction::new("block_ip", "firewall"));
        let outcome = action.execute(&system_ctx(), &sample_params()).unwrap();
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

        let results = registry.invoke(&system_ctx(), "block_ip", &sample_params());

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
        assert!(
            registry
                .invoke(&system_ctx(), "isolate_host", &sample_params())
                .is_empty()
        );
    }

    #[test]
    fn test_invoke_reports_invalid_params_without_reaching_execute_logic() {
        let mut registry = ActionRegistry::new();
        let action = Arc::new(CountingAction::new("block_ip", "firewall"));
        registry.register(action.clone());

        let results = registry.invoke(&system_ctx(), "block_ip", &FieldMap::new());

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

        registry.invoke(&system_ctx(), "block_ip", &sample_params());
        action.execute(&system_ctx(), &sample_params()).unwrap();

        assert_eq!(action.call_count(), 2);
    }

    #[test]
    fn test_list_for_hides_denied_and_keeps_allowed() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(CountingAction::new("block_ip", "firewall")));
        let authz = RoleAuthorizer::new().with_default_roles();

        let viewer_ctx = InvocationContext::new(Principal::user("alice", ["viewer"]));
        assert!(registry.list_for(&viewer_ctx, &authz).is_empty());

        let responder_ctx = InvocationContext::new(Principal::user("bob", ["responder"]));
        assert_eq!(registry.list_for(&responder_ctx, &authz).len(), 1);
    }

    #[test]
    fn test_invoke_as_denies_without_calling_execute_and_still_audits() {
        let mut registry = ActionRegistry::new();
        let action = Arc::new(CountingAction::new("block_ip", "firewall"));
        registry.register(action.clone());
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = InvocationContext::new(Principal::user("alice", ["viewer"]));

        let results = registry.invoke_as(&ctx, &authz, "block_ip", &sample_params());

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0].result,
            Err(ActionError::Unauthorized(_))
        ));
        assert_eq!(action.call_count(), 0);
        assert_eq!(
            results[0]
                .audit
                .get_field("authz.decision")
                .and_then(|f| f.as_str()),
            Some("deny")
        );
        assert_eq!(
            results[0]
                .audit
                .get_field("principal.id")
                .and_then(|f| f.as_str()),
            Some("alice")
        );
    }

    #[test]
    fn test_invoke_as_requires_approval_for_agent_on_destructive_action() {
        let mut registry = ActionRegistry::new();
        let action = Arc::new(CountingAction::new("block_ip", "firewall"));
        registry.register(action.clone());
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = InvocationContext::new(Principal::agent("copilot", ["responder"]));

        let results = registry.invoke_as(&ctx, &authz, "block_ip", &sample_params());

        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0].result,
            Err(ActionError::ApprovalRequired(_))
        ));
        assert_eq!(action.call_count(), 0);
        assert_eq!(
            results[0]
                .audit
                .get_field("authz.decision")
                .and_then(|f| f.as_str()),
            Some("require_approval")
        );
    }

    #[test]
    fn test_invoke_as_allows_and_audits_a_granted_call() {
        let mut registry = ActionRegistry::new();
        let action = Arc::new(CountingAction::new("block_ip", "firewall"));
        registry.register(action.clone());
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = InvocationContext::new(Principal::user("bob", ["responder"]))
            .with_reason("contain active intrusion");

        let results = registry.invoke_as(&ctx, &authz, "block_ip", &sample_params());

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].result, Ok(outcome) if outcome.is_success()));
        assert_eq!(action.call_count(), 1);
        assert_eq!(
            results[0]
                .audit
                .get_field("authz.decision")
                .and_then(|f| f.as_str()),
            Some("allow")
        );
        assert_eq!(
            results[0]
                .audit
                .get_field("action.reason")
                .and_then(|f| f.as_str()),
            Some("contain active intrusion")
        );
    }

    #[test]
    fn test_required_permission_defaults_to_action_invoke_name() {
        let descriptor = ActionDescriptor::builder("block_ip", "firewall", "blocks an ip").build();
        assert_eq!(descriptor.required_permission(), "action.invoke:block_ip");

        let custom = ActionDescriptor::builder("block_ip", "firewall", "blocks an ip")
            .permission("custom.perm")
            .build();
        assert_eq!(custom.required_permission(), "custom.perm");
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
