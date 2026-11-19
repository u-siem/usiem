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
//! - [`rating`] provides the shared rating scales: [`rating::Severity`]
//!   (with its [`rating::Criticality`]/[`rating::RiskLevel`] aliases) and
//!   [`rating::Confidence`], used by signals, incidents and enrichment types.
//! - [`entity`] provides [`entity::EntityRef`]: the host, user, address or
//!   device a finding concerns, normalised so the same one compares equal
//!   across logs.
//! - [`message`] provides [`message::LocalizedMessage`], a language-
//!   independent message shared by `signal` and `action`.
//! - [`action`] provides [`action::Action`]/[`action::ActionRegistry`]: a
//!   discoverable, plug-and-play contract meant to be the SIEM's *one*
//!   interaction surface — response actions (e.g. "block this IP"),
//!   admin/config commands, and read-only queries (e.g. "search logs")
//!   alike. A capability name can have many registered providers, and
//!   [`action::ActionRegistry::invoke`] fans out to all of them — this
//!   crate ships no concrete actions, no fixed vocabulary of capability
//!   names, no aggregation policy across providers, and no global/singleton
//!   registry instance.
//! - [`lookup`] provides [`lookup::LookupPoint`]/[`lookup::SegmentedPipeline`]:
//!   lookups that may need async I/O (DNS, REST APIs), done by parking the
//!   event and resuming it, never by awaiting inside a stage. Std-only:
//!   [`lookup::AsyncLookup`] returns a plain `Future` the host drives.
//! - [`workers`] provides [`workers::Queue`] (bounded, std-only MPMC) and
//!   [`workers::WorkerPool`]: the threads that run synchronous processing,
//!   fed in batches.
//!
//! # Sync processing, async I/O
//!
//! Event processing in uSIEM is synchronous and std-only. Stages run on OS
//! threads fed from bounded queues, and no stage ever `.await`s. Async I/O
//! (network intake, APIs, external lookups) belongs to the host
//! application, and the two sides meet only at queues:
//! - async to sync: a non-blocking `try_push` into a bounded queue;
//! - sync to async: a non-blocking send.
//!
//! An async lookup is a point where an event leaves the pipeline and comes
//! back later, not an `.await` inside a stage.

pub mod action;
pub mod context;
pub mod enrichment;
pub mod entity;
pub mod lookup;
pub mod message;
pub mod pipeline;
pub mod rating;
pub mod signal;
pub mod workers;
