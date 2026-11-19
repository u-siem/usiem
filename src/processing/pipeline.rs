//! A minimal, ordered event-processing pipeline.
//!
//! # Design
//!
//! Like [`crate::ingest::parser::LogParser`], a [`Processor`] wraps a shared
//! closure (a plain `fn` item works too), so a stage can carry its own
//! configuration or a handle to a dataset. A [`Pipeline`] runs a named,
//! ordered sequence of [`Processor`]s over an [`Event`], counting per stage
//! how many events it saw, dropped and failed, and how long it took
//! ([`StageStats`]).
//!
//! [`Pipeline::run`] takes `&self`: one pipeline can be shared by every
//! worker thread. The counters are atomics.
//!
//! This is intentionally unopinionated about what a stage *does* — enrichment,
//! filtering, correlation, and field derivation can all be expressed as a
//! `ProcessorFn`. This module only provides the ordering/instrumentation seam
//! between parsing and any downstream processing.
//!
//! # Example
//!
//! ```
//! use usiem::processing::pipeline::{Pipeline, ProcessResult, Processor};
//! use usiem::event::{CoreEvent as Event, Origin, RawData};
//! use usiem::event::field::{FieldValue, Timestamp};
//!
//! let threshold = 8; // configuration captured by the stage
//! let mut pipeline = Pipeline::new();
//! pipeline.add_stage(Processor::new(
//!     "tag_high_severity",
//!     "Flags events with severity >= threshold",
//!     move |mut event: Event| {
//!         let is_high = matches!(event.get_field("severity"), Some(FieldValue::Int(n)) if *n >= threshold);
//!         event.add_field("severity.is_high", FieldValue::Bool(is_high));
//!         ProcessResult::Continue(event)
//!     },
//! ));
//!
//! let mut event = Event::new(
//!     Timestamp::now(),
//!     Timestamp::now(),
//!     Origin::from_hostname("host1"),
//!     RawData::from_text("raw log"),
//! );
//! event.add_field("severity", FieldValue::Int(9));
//!
//! match pipeline.run(event) {
//!     ProcessResult::Continue(event) => {
//!         assert_eq!(event.get_field("severity.is_high"), Some(&FieldValue::Bool(true)));
//!     }
//!     other => panic!("expected the event to continue, got {other:?}"),
//! }
//! assert_eq!(pipeline.stats()[0].1.runs(), 1);
//! ```

use crate::event::CoreEvent as Event;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A pipeline stage's function: takes ownership of an `Event`.
pub type ProcessorFn = std::sync::Arc<dyn Fn(Event) -> ProcessResult + Send + Sync>;

/// A single named pipeline stage wrapping a processing function.
///
/// Mirrors [`crate::ingest::parser::LogParser`]'s design: an identity plus a
/// shared closure.
#[derive(Clone)]
pub struct Processor {
    /// Unique, stable name for this stage — it labels the stage's
    /// [`StageStats`], so it should be a `'static` identifier rather than
    /// anything derived from event content.
    pub name: &'static str,

    /// Human-readable description of what this stage does.
    pub description: &'static str,

    /// The actual processing function.
    pub process_fn: ProcessorFn,
}

impl Processor {
    /// Create a new processing stage with the given function.
    pub fn new(
        name: &'static str,
        description: &'static str,
        process_fn: impl Fn(Event) -> ProcessResult + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            description,
            process_fn: std::sync::Arc::new(process_fn),
        }
    }
}

impl std::fmt::Debug for Processor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Processor")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The outcome of running a single [`Processor`] over an event.
#[derive(Debug)]
pub enum ProcessResult {
    /// The stage succeeded; pass the (possibly modified) event to the next stage.
    Continue(Event),
    /// The stage decided this event should not continue through the pipeline
    /// (e.g. filtered out, deduplicated). Processing stops here for this event.
    Drop(String),
    /// The stage failed. Processing stops here for this event.
    Error(String),
}

/// Cumulative counters for one stage, across every event and thread.
#[derive(Debug, Default)]
pub struct StageStats {
    runs: AtomicU64,
    drops: AtomicU64,
    errors: AtomicU64,
    nanos: AtomicU64,
}

impl StageStats {
    /// Events this stage was run on.
    pub fn runs(&self) -> u64 {
        self.runs.load(Ordering::Relaxed)
    }

    /// Events this stage dropped.
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Events this stage failed on.
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Total time spent in this stage; zero when timing is off
    /// ([`Pipeline::without_timing`]).
    pub fn total_time(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }
}

/// An ordered sequence of [`Processor`] stages, run over one [`Event`] at a time.
///
/// A `Pipeline` is intentionally simple: it does not itself provide branching,
/// retries, or parallelism. Those concerns belong to whatever code constructs
/// the pipeline and decides which stages to register.
pub struct Pipeline {
    stages: Vec<(Processor, StageStats)>,
    timing: bool,
}

impl Pipeline {
    /// Create a new, empty pipeline that times its stages.
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            timing: true,
        }
    }

    /// Create a new, empty pipeline that counts but doesn't time its stages
    /// (saves two clock reads per stage and event).
    pub fn without_timing() -> Self {
        Self {
            stages: Vec::new(),
            timing: false,
        }
    }

    /// Append a stage to the end of the pipeline.
    pub fn add_stage(&mut self, processor: Processor) -> &mut Self {
        self.stages.push((processor, StageStats::default()));
        self
    }

    /// The registered stages, in run order.
    pub fn stages(&self) -> impl ExactSizeIterator<Item = &Processor> {
        self.stages.iter().map(|(p, _)| p)
    }

    /// Whether the pipeline has no stages.
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// Every stage's name and counters, in run order.
    pub fn stats(&self) -> Vec<(&'static str, &StageStats)> {
        self.stages.iter().map(|(p, s)| (p.name, s)).collect()
    }

    /// A [`crate::capability::ComponentManifest`] for every registered
    /// stage, derived from the `name`/`description` it already carries — this
    /// is how a `Pipeline` participates in the capability catalog. See
    /// `crate::capability` module docs.
    pub fn manifests(&self) -> Vec<crate::capability::ComponentManifest> {
        self.stages()
            .map(|stage| {
                crate::capability::ComponentManifest::new(
                    format!("processor/{}", stage.name),
                    crate::capability::ComponentKind::Processor,
                    stage.name,
                    stage.description,
                )
            })
            .collect()
    }

    /// Run every stage in order over `event`, stopping early on [`ProcessResult::Drop`]
    /// or [`ProcessResult::Error`].
    pub fn run(&self, mut event: Event) -> ProcessResult {
        for (stage, stats) in &self.stages {
            stats.runs.fetch_add(1, Ordering::Relaxed);
            let started = self.timing.then(Instant::now);
            let result = (stage.process_fn)(event);
            if let Some(started) = started {
                let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                stats.nanos.fetch_add(nanos, Ordering::Relaxed);
            }
            match result {
                ProcessResult::Continue(next_event) => event = next_event,
                ProcessResult::Drop(reason) => {
                    stats.drops.fetch_add(1, Ordering::Relaxed);
                    crate::log_debug!(
                        "pipeline",
                        "stage '{}' dropped the event: {}",
                        stage.name,
                        reason
                    );
                    return ProcessResult::Drop(reason);
                }
                ProcessResult::Error(reason) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    crate::log_warn!("pipeline", "stage '{}' failed: {}", stage.name, reason);
                    return ProcessResult::Error(reason);
                }
            }
        }
        ProcessResult::Continue(event)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Origin;
    use crate::event::RawData;
    use crate::event::field::{FieldValue, Timestamp};

    fn sample_event() -> Event {
        Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_hostname("test-host"),
            RawData::from_text("raw log line"),
        )
    }

    fn add_marker(mut event: Event) -> ProcessResult {
        event.add_field("marker", FieldValue::str("seen"));
        ProcessResult::Continue(event)
    }

    fn always_drop(_event: Event) -> ProcessResult {
        ProcessResult::Drop("filtered".to_string())
    }

    fn always_error(_event: Event) -> ProcessResult {
        ProcessResult::Error("boom".to_string())
    }

    fn stats_of<'a>(pipeline: &'a Pipeline, name: &str) -> &'a StageStats {
        pipeline
            .stats()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, s)| s)
            .unwrap()
    }

    #[test]
    fn test_empty_pipeline_returns_event_unchanged() {
        let pipeline = Pipeline::new();
        match pipeline.run(sample_event()) {
            ProcessResult::Continue(event) => assert!(event.get_field("marker").is_none()),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn test_stages_run_in_order_and_count() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        for _ in 0..3 {
            match pipeline.run(sample_event()) {
                ProcessResult::Continue(event) => {
                    assert_eq!(event.get_field("marker"), Some(&FieldValue::str("seen")));
                }
                _ => panic!("expected Continue"),
            }
        }
        let stats = stats_of(&pipeline, "marker");
        assert_eq!(stats.runs(), 3);
        assert_eq!(stats.drops() + stats.errors(), 0);
    }

    #[test]
    fn test_stage_can_capture_configuration() {
        let tag = String::from("from-config");
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new(
            "tag",
            "adds a configured tag",
            move |mut event| {
                event.add_field("tag", FieldValue::string(tag.clone()));
                ProcessResult::Continue(event)
            },
        ));

        match pipeline.run(sample_event()) {
            ProcessResult::Continue(event) => {
                assert_eq!(
                    event.get_field("tag"),
                    Some(&FieldValue::str("from-config"))
                );
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn test_drop_stops_pipeline() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("gate", "drops everything", always_drop));
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Drop(reason) => assert_eq!(reason, "filtered"),
            _ => panic!("expected Drop"),
        }

        // The second stage never ran because the first stage dropped the event.
        assert_eq!(stats_of(&pipeline, "marker").runs(), 0);
        assert_eq!(stats_of(&pipeline, "gate").drops(), 1);
    }

    #[test]
    fn test_error_stops_pipeline() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("boom", "always errors", always_error));
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Error(reason) => assert_eq!(reason, "boom"),
            _ => panic!("expected Error"),
        }

        assert_eq!(stats_of(&pipeline, "marker").runs(), 0);
        assert_eq!(stats_of(&pipeline, "boom").errors(), 1);
    }

    #[test]
    fn test_without_timing_still_runs_and_counts() {
        let mut pipeline = Pipeline::without_timing();
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Continue(event) => {
                assert_eq!(event.get_field("marker"), Some(&FieldValue::str("seen")));
            }
            _ => panic!("expected Continue"),
        }
        let stats = stats_of(&pipeline, "marker");
        assert_eq!(stats.runs(), 1);
        assert_eq!(stats.total_time(), std::time::Duration::ZERO);
    }

    #[test]
    fn test_pipeline_is_shareable_across_threads() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));
        let pipeline = std::sync::Arc::new(pipeline);
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let pipeline = pipeline.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        assert!(matches!(
                            pipeline.run(sample_event()),
                            ProcessResult::Continue(_)
                        ));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(stats_of(&pipeline, "marker").runs(), 200);
    }
}
