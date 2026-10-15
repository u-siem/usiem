//! # uSIEM
//!
//! A modular, high-performance Security Information and Event Management (SIEM)
//! framework. `usiem` provides the core building blocks for constructing custom
//! SIEM solutions — it is a library, not a standalone application: it defines
//! types and parsing/enrichment logic, but leaves collection, correlation, and
//! output to the consuming application.
//!
//! # Crate structure
//!
//! - [`event`] — the core data model: [`event::Event`], [`event::RawEvent`],
//!   [`event::field::FieldValue`] (the typed field-value system), [`event::Origin`],
//!   and [`event::Schema`] for optional validation.
//! - [`ingest`] — turns raw log text into events: [`ingest::parser::LogParser`]
//!   for content parsing (Apache, JSON, Windows Event Log) and
//!   [`ingest::parser::transport`] for transport-layer parsing (Syslog RFC3164/RFC5424).
//!   [`ingest::collector::Collector`] is the interface for acquiring raw log
//!   data in the first place — this crate has no built-in I/O (no network
//!   listeners or file tailing) and ships no concrete collectors.
//! - [`processing`] — event enrichment, pipeline orchestration, and output:
//!   [`processing::enrichment`] provides a dataset/registry framework for
//!   enriching events with external lookup data (e.g. GeoIP, threat
//!   intelligence), [`processing::pipeline`] provides an ordered,
//!   instrumented processing-stage extension point,
//!   [`processing::signal`] provides
//!   [`processing::signal::Signal`] (an event, or cluster of events,
//!   evaluated against context/threat intelligence and flagged suspicious —
//!   not yet an alarm), [`processing::incident`] provides
//!   [`processing::incident::Incident`] (an analyst-facing aggregate of
//!   events/signals, independent of `Signal`), [`processing::message`]
//!   provides [`processing::message::LocalizedMessage`] (shared by
//!   `Signal`/`Incident`/`ActionOutcome`) and a small, centralized
//!   [`processing::message::Template`]/[`processing::message::TemplateRegistry`]
//!   catalog/renderer, [`processing::sink`] is the interface for shipping
//!   events to an external destination, and [`processing::action`] provides
//!   [`processing::action::Action`]/[`processing::action::ActionRegistry`]
//!   for firing a discoverable, plug-and-play response action/command.
//! - [`observability`] — a minimal, dependency-free internal logging facade
//!   (mirrors the `log` crate's shape, but hand-rolled rather than pulling in
//!   an external dependency). Nothing is emitted unless a consuming
//!   application installs a [`observability::Logger`].
//! - [`security`] — authorization only, not authentication:
//!   [`security::Principal`]/[`security::Role`]/[`security::Permission`] and
//!   the [`security::Authorizer`] trait ([`security::RoleAuthorizer`] is this
//!   crate's own bundled static-RBAC implementation), consulted by
//!   [`processing::action::ActionRegistry::list_for`]/
//!   [`processing::action::ActionRegistry::invoke_as`].
//! - [`capability`] — [`capability::CapabilityCatalog`]/[`capability::Component`]:
//!   a uniform, self-describing manifest for every kind of component
//!   (collectors, parsers, sinks, datasets, action providers), so an MCP
//!   server or an AI-driven UI/CLI has one place to discover what a running
//!   SIEM is made of.
//!
//! # Quick start
//!
//! ```
//! use usiem::prelude::*;
//!
//! let mut registry = ParserRegistry::new();
//! registry.register(apache_common_parser());
//!
//! let raw = RawEvent::from_log(
//!     r#"127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET / HTTP/1.1" 200 2326"#,
//!     "access.log",
//! );
//!
//! match registry.parse(raw) {
//!     ParseResult::Success(event) => {
//!         assert_eq!(event.get_field("client.ip").and_then(|f| f.as_str()), Some("127.0.0.1"));
//!     }
//!     _ => panic!("expected a match"),
//! }
//! ```

pub mod capability;
pub mod event;
pub mod ingest;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod observability;
pub mod processing;
pub mod security;

// Re-export commonly used types for easy access
pub mod prelude {
    // Core event types
    pub use crate::event::field::{FieldMap, FieldValue, Ip, Timestamp};
    pub use crate::event::{Event, EventId, Origin, RawEvent};

    // Parsing system
    pub use crate::ingest::parser::common_parsers::*;
    pub use crate::ingest::parser::registry::{ParserRegistry, ParserRegistryConfig};
    pub use crate::ingest::parser::result::ParseResult;
    pub use crate::ingest::parser::transport::{
        TransportParser, TransportParserFn, TransportResult,
    };
    pub use crate::ingest::parser::transport_parsers::*;
    pub use crate::ingest::parser::transport_registry::{
        TransportRegistry, TransportRegistryConfig,
    };
    pub use crate::ingest::parser::{LogParser, ParserFn};

    // Event schema
    pub use crate::event::{
        FieldConstraints, Schema, SchemaError, SchemaField, SchemaFieldBuilder, SchemaFieldType,
    };

    // Processing pipeline
    pub use crate::processing::pipeline::{Pipeline, ProcessResult, Processor, ProcessorFn};

    // Output
    pub use crate::processing::sink::Sink;

    // Response actions/commands
    pub use crate::processing::action::{
        Action, ActionDescriptor, ActionDescriptorBuilder, ActionError, ActionInvocationResult,
        ActionOutcome, ActionRegistry, ActionStatus, AuthorizedInvocationResult,
    };

    // Who's calling — threaded through every `Action::execute`
    pub use crate::processing::context::{CancellationHandle, InvocationContext, TenantId};

    // Authorization: principals, roles, permissions, and the Authorizer trait
    pub use crate::security::{
        AllowAll, AuthzRequest, Decision, Permission, PermissionPattern, Principal, PrincipalKind,
        Role, RoleAuthorizer,
    };

    // Capability catalog: every component's self-description
    pub use crate::capability::{
        CapabilityCatalog, Component, ComponentHealth, ComponentId, ComponentKind,
        ComponentManifest, DatasetDescriptor, Dependency, PermissionDef, SchemaRef,
    };

    // Collection
    pub use crate::ingest::collector::Collector;

    // Incident/signal
    pub use crate::processing::incident::{Evidence, Incident, IncidentId};
    pub use crate::processing::signal::{Confidence, EventRef, Severity, Signal, SignalId};

    // Localized messages and message-catalog rendering
    pub use crate::processing::message::{
        LocalizedMessage, Template, TemplateError, TemplateRegistry,
    };

    // Observability
    pub use crate::observability::{Level as LogLevel, Logger, set_logger, set_max_level};
}
