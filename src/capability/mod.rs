//! A single, uniform way for every component in a SIEM built on this crate
//! to announce what it is and what it can do — the capability catalog.
//!
//! # Why this exists
//!
//! [`crate::processing::action::ActionRegistry`] already lets a caller
//! discover and invoke *actions*. But a real deployment is built from many
//! kinds of component — parsers, collectors, sinks, enrichment datasets,
//! pipeline stages — and until now only actions described themselves. An
//! MCP server, an AI composing a UI/CLI on the fly, or just an operator
//! asking "what is this SIEM made of right now" had no single place to ask.
//!
//! This mirrors what an earlier (non-Rust) uSIEM project did with per-
//! component capability registration into a global kernel — see
//! [`crate::processing::action`]'s module docs for why that project's
//! *kernel* (a global mutable singleton) isn't repeated here. The same fix
//! applies: [`CapabilityCatalog`] is a plain, `Default`-constructible struct
//! application code owns and populates explicitly, not a singleton.
//!
//! # Design
//!
//! [`Component`] is the trait a *stateful* integration (a [`crate::ingest::collector::Collector`],
//! a [`crate::processing::sink::Sink`], an enrichment dataset) additionally
//! implements to describe itself — it adds nothing to those traits'
//! required methods; a type can implement `Collector` without ever
//! implementing `Component`, and vice versa is meaningless without also
//! being one of the stateful traits.
//!
//! Stateless, hot-path stages ([`crate::ingest::parser::LogParser`],
//! [`crate::processing::pipeline::Processor`],
//! [`crate::ingest::parser::transport::TransportParser`]) stay plain `fn`
//! pointers, per this crate's established convention — they do not
//! implement `Component`. Instead, their registries
//! ([`crate::ingest::parser::registry::ParserRegistry`],
//! [`crate::processing::pipeline::Pipeline`],
//! [`crate::ingest::parser::transport_registry::TransportRegistry`]) each
//! grow a `manifests()` method that derives a [`ComponentManifest`] per
//! registered stage from the `id`/`name`/`description` fields they already
//! carry, with no new trait involved.
//!
//! [`CapabilityCatalog`] itself registers a small number of built-in,
//! read-only introspection actions (`siem.list_components`,
//! `siem.component_health`) into its own
//! [`crate::processing::action::ActionRegistry`] — so "what can this SIEM
//! do" is itself just another capability, reachable the same way as
//! everything else, per [`crate::processing::action`]'s "one interaction
//! surface" design.
//!
//! # What's deliberately not here
//!
//! No `describe_schema` introspection action ships yet: doing that usefully
//! needs a registry of actual [`crate::event::Schema`] values keyed by
//! [`SchemaRef`], not just the name/version pair a manifest carries, and no
//! such registry exists in this crate yet. [`ComponentManifest::produces`]
//! still records the `SchemaRef`s a component is known to produce, so that
//! registry (and the introspection action built on it) is a well-scoped
//! future addition rather than something to bolt on speculatively now.

use crate::event::field::Text;
use crate::processing::action::{Action, ActionDescriptor, ActionOutcome, ActionRegistry};
use crate::processing::context::InvocationContext;
use crate::processing::message::LocalizedMessage;
use std::sync::{Arc, Mutex};

/// What kind of thing a [`ComponentManifest`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentKind {
    Collector,
    TransportParser,
    Parser,
    Processor,
    Dataset,
    Sink,
    ActionProvider,
    Custom(Text),
}

impl ComponentKind {
    pub fn as_str(&self) -> &str {
        match self {
            ComponentKind::Collector => "collector",
            ComponentKind::TransportParser => "transport_parser",
            ComponentKind::Parser => "parser",
            ComponentKind::Processor => "processor",
            ComponentKind::Dataset => "dataset",
            ComponentKind::Sink => "sink",
            ComponentKind::ActionProvider => "action_provider",
            ComponentKind::Custom(name) => name.as_str(),
        }
    }
}

/// A stable identifier for one component instance, e.g.
/// `"sink/elasticsearch"`, `"parser/apache_common"`. An ecosystem
/// convention, not an enforced format — the same convention as
/// [`crate::processing::action::ActionDescriptor::provider`], which
/// [`CapabilityCatalog::register`] expects a component's self-registered
/// actions to match.
pub type ComponentId = Text;

/// A reference to a named, versioned schema a component is known to
/// produce or consume — e.g. a parser's output shape. Deliberately just a
/// name/version pair, not the [`crate::event::Schema`] itself; see the
/// module docs for why resolving it into a real schema is future work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRef {
    pub name: Text,
    pub version: Text,
}

impl SchemaRef {
    pub fn new(name: impl Into<Text>, version: impl Into<Text>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// A named enrichment dataset a component exposes, e.g. GeoIP or threat
/// intel — deliberately shallow, mirroring
/// [`crate::processing::enrichment::registry::EnrichmentRegistry::dataset_names`]'s
/// own name-only view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetDescriptor {
    pub name: Text,
    pub description: Text,
}

impl DatasetDescriptor {
    pub fn new(name: impl Into<Text>, description: impl Into<Text>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

/// A component (by kind and name) another component depends on to function,
/// e.g. a `Sink` that requires a `"threat_intel"` dataset to be registered
/// to enrich what it ships. Purely descriptive — nothing in this crate
/// resolves or enforces dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub kind: ComponentKind,
    pub name: Text,
    pub required: bool,
}

/// A permission a component defines and expects an
/// [`crate::security::Authorizer`] to be configured to grant/deny — purely
/// documentation for whoever is writing roles; nothing in this crate
/// enforces that a permission named here is actually the one checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDef {
    pub name: Text,
    pub description: Text,
}

impl PermissionDef {
    pub fn new(name: impl Into<Text>, description: impl Into<Text>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

/// A live component's self-reported health, for the
/// `siem.component_health` introspection action. `Unknown` is the default —
/// a component that hasn't implemented anything smarter than "I exist" is
/// not assumed healthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentHealth {
    Unknown,
    Healthy,
    Degraded(Text),
    Unhealthy(Text),
}

impl ComponentHealth {
    pub fn as_str(&self) -> &str {
        match self {
            ComponentHealth::Unknown => "unknown",
            ComponentHealth::Healthy => "healthy",
            ComponentHealth::Degraded(_) => "degraded",
            ComponentHealth::Unhealthy(_) => "unhealthy",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            ComponentHealth::Degraded(msg) | ComponentHealth::Unhealthy(msg) => Some(msg.as_str()),
            _ => None,
        }
    }
}

/// Static metadata describing one component: what it is, what it provides,
/// what it needs, and what permissions govern it. See the module docs for
/// the overall design and [`Component`] for how a stateful component
/// produces one.
#[derive(Debug, Clone)]
pub struct ComponentManifest {
    pub id: ComponentId,
    pub kind: ComponentKind,
    pub name: Text,
    pub description: Text,
    pub version: Text,
    /// This component's own action capabilities — informational; the
    /// authoritative list of *invocable* actions is always
    /// [`crate::processing::action::ActionRegistry::list`], which
    /// [`CapabilityCatalog::register`] populates from
    /// [`Component::actions`] at registration time.
    pub actions: Vec<ActionDescriptor>,
    pub datasets: Vec<DatasetDescriptor>,
    pub produces: Vec<SchemaRef>,
    pub requires: Vec<Dependency>,
    pub permissions: Vec<PermissionDef>,
}

impl ComponentManifest {
    /// A manifest with no actions/datasets/schemas/dependencies/permissions
    /// declared — the common case for a stateless fn-pointer stage, and a
    /// starting point for a stateful [`Component`] to fill in via its own
    /// builder-style construction.
    pub fn new(
        id: impl Into<ComponentId>,
        kind: ComponentKind,
        name: impl Into<Text>,
        description: impl Into<Text>,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            name: name.into(),
            description: description.into(),
            version: Text::from("1"),
            actions: Vec::new(),
            datasets: Vec::new(),
            produces: Vec::new(),
            requires: Vec::new(),
            permissions: Vec::new(),
        }
    }
}

/// Framework interface for a stateful component to describe itself. See the
/// module docs for why stateless fn-pointer stages don't implement this.
pub trait Component: Send + Sync {
    /// Static self-description. Cheap enough to call for every catalog
    /// listing — mirrors [`crate::processing::action::Action::descriptor`].
    fn manifest(&self) -> ComponentManifest;

    /// Actions this component provides, self-registered into the
    /// catalog's [`crate::processing::action::ActionRegistry`] by
    /// [`CapabilityCatalog::register`] — the old u-siem "announce what I can
    /// do" mechanism, without a global kernel. Empty by default: many
    /// components (a plain `GeoIpDataset`) have nothing to invoke.
    fn actions(&self) -> Vec<Arc<dyn Action>> {
        Vec::new()
    }

    /// This component's current health, for `siem.component_health`.
    /// `Unknown` by default — see [`ComponentHealth`].
    fn health(&self) -> ComponentHealth {
        ComponentHealth::Unknown
    }
}

/// A named, runtime-discoverable catalog of every registered [`Component`],
/// plus the [`crate::processing::action::ActionRegistry`] their own actions
/// self-register into. See the module docs for the overall design.
pub struct CapabilityCatalog {
    components: Arc<Mutex<Vec<Arc<dyn Component>>>>,
    actions: ActionRegistry,
}

impl CapabilityCatalog {
    /// A new, empty catalog — already carrying the built-in
    /// `siem.list_components`/`siem.component_health` introspection
    /// actions (see the module docs for why `describe_schema` isn't one of
    /// them yet).
    pub fn new() -> Self {
        let components: Arc<Mutex<Vec<Arc<dyn Component>>>> = Arc::new(Mutex::new(Vec::new()));
        let mut actions = ActionRegistry::new();
        actions.register(Arc::new(ListComponentsAction {
            components: components.clone(),
        }));
        actions.register(Arc::new(ComponentHealthAction {
            components: components.clone(),
        }));
        Self {
            components,
            actions,
        }
    }

    /// Register a component: records it for [`CapabilityCatalog::manifests`]/
    /// [`CapabilityCatalog::health`], and self-registers every action it
    /// provides ([`Component::actions`]) into
    /// [`CapabilityCatalog::actions`].
    pub fn register(&mut self, component: Arc<dyn Component>) {
        for action in component.actions() {
            self.actions.register(action);
        }
        self.components
            .lock()
            .expect("capability catalog mutex poisoned")
            .push(component);
    }

    /// Every registered component's current manifest.
    pub fn manifests(&self) -> Vec<ComponentManifest> {
        self.components
            .lock()
            .expect("capability catalog mutex poisoned")
            .iter()
            .map(|c| c.manifest())
            .collect()
    }

    /// Every registered component's id and current health.
    pub fn health(&self) -> Vec<(ComponentId, ComponentHealth)> {
        self.components
            .lock()
            .expect("capability catalog mutex poisoned")
            .iter()
            .map(|c| (c.manifest().id, c.health()))
            .collect()
    }

    /// The catalog's action registry — every registered component's
    /// self-provided actions, plus the built-in introspection actions.
    pub fn actions(&self) -> &ActionRegistry {
        &self.actions
    }

    /// Mutable access, for registering additional actions directly (e.g.
    /// ones not tied to any one [`Component`]).
    pub fn actions_mut(&mut self) -> &mut ActionRegistry {
        &mut self.actions
    }
}

impl Default for CapabilityCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in read-only introspection action: every registered component's
/// manifest, reported as [`ActionOutcome::data`] under `"components"`.
struct ListComponentsAction {
    components: Arc<Mutex<Vec<Arc<dyn Component>>>>,
}

impl Action for ListComponentsAction {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "siem.list_components",
            "capability_catalog",
            "Lists every registered component and what it provides",
        )
        .read_only()
        .idempotent()
        .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        _params: &crate::event::field::FieldMap,
    ) -> Result<ActionOutcome, crate::processing::action::ActionError> {
        use crate::event::field::FieldValue;

        let manifests: Vec<FieldValue> = self
            .components
            .lock()
            .expect("capability catalog mutex poisoned")
            .iter()
            .map(|c| {
                let m = c.manifest();
                FieldValue::string(format!("{} ({}): {}", m.id, m.kind.as_str(), m.description))
            })
            .collect();
        let count = manifests.len();

        let message = LocalizedMessage::new(
            "capability_catalog.list_components",
            "en-US",
            format!("{count} component(s) registered"),
        );
        let outcome =
            ActionOutcome::success(message).with_data("components", FieldValue::Array(manifests));
        Ok(outcome)
    }
}

/// Built-in read-only introspection action: every registered component's id
/// and current [`ComponentHealth`].
struct ComponentHealthAction {
    components: Arc<Mutex<Vec<Arc<dyn Component>>>>,
}

impl Action for ComponentHealthAction {
    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::builder(
            "siem.component_health",
            "capability_catalog",
            "Reports every registered component's self-reported health",
        )
        .read_only()
        .idempotent()
        .build()
    }

    fn execute(
        &self,
        _ctx: &InvocationContext,
        _params: &crate::event::field::FieldMap,
    ) -> Result<ActionOutcome, crate::processing::action::ActionError> {
        use crate::event::field::FieldValue;

        let statuses: Vec<FieldValue> = self
            .components
            .lock()
            .expect("capability catalog mutex poisoned")
            .iter()
            .map(|c| {
                let id = c.manifest().id;
                let health = c.health();
                FieldValue::string(format!("{id}: {}", health.as_str()))
            })
            .collect();

        let message = LocalizedMessage::new(
            "capability_catalog.component_health",
            "en-US",
            "component health snapshot",
        );
        let outcome =
            ActionOutcome::success(message).with_data("health", FieldValue::Array(statuses));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Principal, PrincipalKind};

    struct ToyDataset {
        healthy: bool,
    }

    impl Component for ToyDataset {
        fn manifest(&self) -> ComponentManifest {
            ComponentManifest::new(
                "dataset/toy",
                ComponentKind::Dataset,
                "toy",
                "an in-memory test dataset",
            )
        }

        fn health(&self) -> ComponentHealth {
            if self.healthy {
                ComponentHealth::Healthy
            } else {
                ComponentHealth::Unhealthy(Text::from("no data loaded"))
            }
        }
    }

    struct ToySink;

    struct ToySinkAction;
    impl Action for ToySinkAction {
        fn descriptor(&self) -> ActionDescriptor {
            ActionDescriptor::builder("flush_sink", "sink/toy", "flushes the toy sink").build()
        }

        fn execute(
            &self,
            _ctx: &InvocationContext,
            _params: &crate::event::field::FieldMap,
        ) -> Result<ActionOutcome, crate::processing::action::ActionError> {
            Ok(ActionOutcome::success(LocalizedMessage::new(
                "toy.flush",
                "en-US",
                "flushed",
            )))
        }
    }

    impl Component for ToySink {
        fn manifest(&self) -> ComponentManifest {
            ComponentManifest::new("sink/toy", ComponentKind::Sink, "toy", "an in-memory sink")
        }

        fn actions(&self) -> Vec<Arc<dyn Action>> {
            vec![Arc::new(ToySinkAction)]
        }
    }

    fn system_ctx() -> InvocationContext {
        InvocationContext::new(Principal::new("system", PrincipalKind::Service))
    }

    #[test]
    fn test_register_collects_manifests_and_health() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register(Arc::new(ToyDataset { healthy: true }));
        catalog.register(Arc::new(ToySink));

        let manifests = catalog.manifests();
        assert_eq!(manifests.len(), 2);

        let health = catalog.health();
        assert!(
            health
                .iter()
                .any(|(id, h)| id == "dataset/toy" && *h == ComponentHealth::Healthy)
        );
    }

    #[test]
    fn test_register_self_registers_component_actions() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register(Arc::new(ToySink));

        assert_eq!(catalog.actions().providers("flush_sink").len(), 1);
    }

    #[test]
    fn test_builtin_list_components_action_reports_registered_components() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register(Arc::new(ToyDataset { healthy: false }));

        let results = catalog.actions().invoke(
            &system_ctx(),
            "siem.list_components",
            &crate::event::field::FieldMap::new(),
        );
        assert_eq!(results.len(), 1);
        let outcome = results[0].result.as_ref().unwrap();
        match outcome.data.get("components") {
            Some(crate::event::field::FieldValue::Array(items)) => assert_eq!(items.len(), 1),
            other => panic!("expected an array of components, got {other:?}"),
        }
    }

    #[test]
    fn test_builtin_component_health_action_reports_health() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register(Arc::new(ToyDataset { healthy: true }));

        let results = catalog.actions().invoke(
            &system_ctx(),
            "siem.component_health",
            &crate::event::field::FieldMap::new(),
        );
        let outcome = results[0].result.as_ref().unwrap();
        match outcome.data.get("health") {
            Some(crate::event::field::FieldValue::Array(items)) => assert_eq!(items.len(), 1),
            other => panic!("expected an array of health entries, got {other:?}"),
        }
    }
}
