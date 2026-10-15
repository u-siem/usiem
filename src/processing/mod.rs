//! Event processing: enrichment, pipeline orchestration, output, and a
//! self-describing action/command surface.
//!
//! - [`enrichment`] is a dataset/registry framework for enriching events with
//!   external lookup data (GeoIP, threat intelligence, etc.).
//! - [`pipeline`] provides the [`pipeline::Pipeline`]/[`pipeline::Processor`]
//!   extension point for composing ordered, instrumented processing stages
//!   over an event — see that module's docs for a worked example.
//! - [`signal`] provides [`signal::Signal`]: an event (or cluster of events)
//!   evaluated against context or threat intelligence and flagged as
//!   potentially suspicious — not yet an explicit alarm.
//! - [`incident`] provides [`incident::Incident`]: an analyst-facing
//!   aggregate of events/signals that an application-defined rule judged
//!   significant enough to surface. Independent of [`signal::Signal`] — this
//!   crate has no built-in "N signals ⇒ incident" policy.
//! - [`message`] provides [`message::LocalizedMessage`] (a language-
//!   independent message shared by `signal`/`incident`/`action`) plus
//!   [`message::Template`]/[`message::TemplateRegistry`]: a small,
//!   centralized message-catalog and placeholder renderer — unlike this
//!   crate's other extension points, a real implementation ships here,
//!   since template rendering has no external-system dependency to keep
//!   out of scope.
//! - [`sink`] provides the [`sink::Sink`] interface for shipping events to an
//!   external destination (stdout, file, Kafka, Elasticsearch, ...) — this
//!   crate has no I/O dependencies and provides no concrete sinks.
//! - [`action`] provides [`action::Action`]/[`action::ActionRegistry`]: a
//!   discoverable, plug-and-play contract meant to be the SIEM's *one*
//!   interaction surface — response actions (e.g. "block this IP"),
//!   admin/config commands, and read-only queries (e.g. "search logs")
//!   alike. A capability name can have many registered providers, and
//!   [`action::ActionRegistry::invoke`] fans out to all of them — this
//!   crate ships no concrete actions, no fixed vocabulary of capability
//!   names, no aggregation policy across providers, and no global/singleton
//!   registry instance.
//! - `metadata` is an unimplemented placeholder; its intended design isn't
//!   documented anywhere yet.

pub mod action;
pub mod context;
pub mod enrichment;
pub mod incident;
pub mod message;
pub mod metadata;
pub mod pipeline;
pub mod signal;
pub mod sink;
