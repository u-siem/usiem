//! # uSIEM
//!
//! A modular, high-performance Security Information and Event Management (SIEM)
//! framework. `usiem` provides the core building blocks for constructing custom
//! SIEM solutions — it is a library, not a standalone application: it defines
//! the event model, parsing, enrichment and processing machinery, and leaves
//! collection, storage, correlation and output to the consuming application.
//!
//! # Crate structure
//!
//! - [`event`] — the core data model: [`event::Event`], [`event::RawEvent`],
//!   [`event::field::FieldValue`] (the typed field-value system), [`event::Origin`],
//!   stable [`event::EventId`]s ([`event::hash`]), well-known field names
//!   ([`event::fields`]) and [`event::Schema`] for optional validation.
//! - [`ingest`] — turns raw log text into events: [`ingest::parser::LogParser`]
//!   for content parsing (Apache, JSON, Windows Event Log, CEF),
//!   [`ingest::parser::transport`] for transport-layer parsing (Syslog
//!   RFC3164/RFC5424) and [`ingest::framing`] for splitting byte streams.
//!   This crate does no I/O: acquiring the bytes is the application's.
//! - [`processing`] — what happens to an event after parsing:
//!   [`processing::enrichment`] (lookup datasets such as GeoIP or CIDR
//!   tables), [`processing::pipeline`] (ordered, instrumented stages),
//!   [`processing::lookup`] (async lookups without `.await` in stages),
//!   [`processing::workers`] (bounded queues and worker threads),
//!   [`processing::signal`] (detection output: an event or cluster of events
//!   flagged suspicious), shared [`processing::rating`]s and
//!   [`processing::entity`] names, and [`processing::action`]
//!   ([`processing::action::Action`]/[`processing::action::ActionRegistry`]:
//!   discoverable response actions and commands).
//! - [`observability`] — a minimal, dependency-free internal logging facade
//!   (mirrors the `log` crate's shape). Nothing is emitted unless a consuming
//!   application installs a [`observability::Logger`].
//! - [`security`] — authorization only, not authentication:
//!   [`security::Principal`]/[`security::Role`]/[`security::Permission`] and
//!   the [`security::Authorizer`] trait ([`security::RoleAuthorizer`] is this
//!   crate's own bundled static-RBAC implementation), consulted by
//!   [`processing::action::ActionRegistry::list_for`]/
//!   [`processing::action::ActionRegistry::invoke_as`].
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

pub mod event;
pub mod ingest;
pub mod observability;
pub mod processing;
pub mod security;

// Re-export commonly used types for easy access
pub mod prelude {
    // Core event types
    pub use crate::event::field::{FieldMap, FieldValue, Ip, Text, Timestamp};
    pub use crate::event::{Event, EventId, Origin, RawData, RawEvent};

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
    pub use crate::processing::pipeline::{
        Pipeline, ProcessResult, Processor, ProcessorFn, StageStats,
    };

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

    // Detection output
    pub use crate::processing::signal::{EventRef, Signal, SignalId};

    // Shared rating scales
    pub use crate::processing::entity::{EntityKind, EntityRef};
    pub use crate::processing::rating::{Confidence, Criticality, RiskLevel, RiskScore, Severity};

    // Localized messages
    pub use crate::processing::message::LocalizedMessage;

    // Observability
    pub use crate::observability::{Level as LogLevel, Logger, set_logger, set_max_level};
}
