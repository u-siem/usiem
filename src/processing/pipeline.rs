//! A minimal, ordered event-processing pipeline.
//!
//! # Design
//!
//! Like [`crate::ingest::parser::LogParser`], a [`Processor`] wraps a plain
//! `fn` pointer rather than a `dyn Trait` — consistent with this crate's
//! existing "no trait overhead" convention for hot-path stages. A [`Pipeline`]
//! runs a named, ordered sequence of [`Processor`]s over an [`Event`],
//! recording per-stage timing and status in a [`PipelineMetadata`].
//!
//! This is intentionally unopinionated about what a stage *does* — enrichment,
//! filtering, correlation, and field derivation can all be expressed as a
//! `ProcessorFn`. This module only provides the ordering/instrumentation seam
//! that was previously missing between parsing and any downstream processing.
//!
//! # Example
//!
//! ```
//! use usiem::processing::pipeline::{Pipeline, ProcessResult, Processor};
//! use usiem::event::{CoreEvent as Event, Origin, RawData};
//! use usiem::event::field::{FieldValue, Timestamp};
//!
//! fn tag_high_severity(mut event: Event) -> ProcessResult {
//!     let is_high = matches!(event.get_field("severity"), Some(FieldValue::Int(n)) if *n >= 8);
//!     event.add_field("severity.is_high".to_string(), FieldValue::Bool(is_high));
//!     ProcessResult::Continue(event)
//! }
//!
//! let mut pipeline = Pipeline::new();
//! pipeline.add_stage(Processor::new(
//!     "tag_high_severity",
//!     "Flags events with severity >= 8",
//!     tag_high_severity,
//! ));
//!
//! let mut event = Event::new(
//!     Timestamp::now(),
//!     Timestamp::now(),
//!     Origin::from_hostname("host1"),
//!     RawData::from_text("raw log"),
//! );
//! event.add_field("severity".to_string(), FieldValue::Int(9));
//!
//! match pipeline.run(event) {
//!     ProcessResult::Continue(event) => {
//!         assert_eq!(event.get_field("severity.is_high"), Some(&FieldValue::Bool(true)));
//!     }
//!     other => panic!("expected the event to continue, got {other:?}"),
//! }
//! ```

use crate::event::CoreEvent as Event;
use crate::event::metadata::PipelineMetadata;

/// Type alias for a pipeline processing stage - takes ownership of an `Event`.
pub type ProcessorFn = fn(Event) -> ProcessResult;

/// A single named pipeline stage wrapping a processing function.
///
/// Mirrors [`crate::ingest::parser::LogParser`]'s design: a plain fn pointer,
/// no trait overhead.
#[derive(Clone)]
pub struct Processor {
    /// Unique, stable name for this stage — used as the key into
    /// [`PipelineMetadata`], so it should be a `'static` identifier rather
    /// than anything derived from event content.
    pub name: &'static str,

    /// Human-readable description of what this stage does.
    pub description: &'static str,

    /// The actual processing function.
    pub process_fn: ProcessorFn,
}

impl Processor {
    /// Create a new processing stage with the given function.
    pub fn new(name: &'static str, description: &'static str, process_fn: ProcessorFn) -> Self {
        Self {
            name,
            description,
            process_fn,
        }
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

/// An ordered sequence of [`Processor`] stages, run over one [`Event`] at a time.
///
/// A `Pipeline` is intentionally simple: it does not itself provide branching,
/// retries, or parallelism. Those concerns belong to whatever code constructs
/// the pipeline and decides which stages to register.
pub struct Pipeline {
    stages: Vec<Processor>,
    metadata: PipelineMetadata,
}

impl Pipeline {
    /// Create a new, empty pipeline with metadata collection enabled.
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            metadata: PipelineMetadata::new(),
        }
    }

    /// Create a new, empty pipeline using the given metadata tracker (for
    /// example, [`PipelineMetadata::disabled`] to skip collection overhead).
    pub fn with_metadata(metadata: PipelineMetadata) -> Self {
        Self {
            stages: Vec::new(),
            metadata,
        }
    }

    /// Append a stage to the end of the pipeline.
    pub fn add_stage(&mut self, processor: Processor) -> &mut Self {
        self.stages.push(processor);
        self
    }

    /// The registered stages, in run order.
    pub fn stages(&self) -> &[Processor] {
        &self.stages
    }

    /// A [`crate::capability::ComponentManifest`] for every registered
    /// stage, derived from the `name`/`description` it already carries —
    /// stages stay plain `fn` pointers (no [`crate::capability::Component`]
    /// impl), so this is how a `Pipeline` participates in the capability
    /// catalog. See `crate::capability` module docs.
    pub fn manifests(&self) -> Vec<crate::capability::ComponentManifest> {
        self.stages
            .iter()
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

    /// Per-stage timing, status, and custom metrics collected across calls to [`Pipeline::run`].
    pub fn metadata(&self) -> &PipelineMetadata {
        &self.metadata
    }

    /// Run every stage in order over `event`, stopping early on [`ProcessResult::Drop`]
    /// or [`ProcessResult::Error`].
    pub fn run(&mut self, mut event: Event) -> ProcessResult {
        for stage in &self.stages {
            self.metadata.start_stage(stage.name);
            match (stage.process_fn)(event) {
                ProcessResult::Continue(next_event) => {
                    self.metadata.complete_stage(stage.name);
                    event = next_event;
                }
                ProcessResult::Drop(reason) => {
                    self.metadata.skip_stage(stage.name);
                    crate::log_debug!(
                        "pipeline",
                        "stage '{}' dropped the event: {}",
                        stage.name,
                        reason
                    );
                    return ProcessResult::Drop(reason);
                }
                ProcessResult::Error(reason) => {
                    self.metadata.fail_stage(stage.name, reason.clone());
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
    use crate::event::metadata::StageStatus;

    fn sample_event() -> Event {
        Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_hostname("test-host"),
            RawData::from_text("raw log line"),
        )
    }

    fn add_marker(mut event: Event) -> ProcessResult {
        event.add_field("marker".to_string(), FieldValue::str("seen"));
        ProcessResult::Continue(event)
    }

    fn always_drop(_event: Event) -> ProcessResult {
        ProcessResult::Drop("filtered".to_string())
    }

    fn always_error(_event: Event) -> ProcessResult {
        ProcessResult::Error("boom".to_string())
    }

    #[test]
    fn test_empty_pipeline_returns_event_unchanged() {
        let mut pipeline = Pipeline::new();
        match pipeline.run(sample_event()) {
            ProcessResult::Continue(event) => assert!(event.get_field("marker").is_none()),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn test_stages_run_in_order_and_record_metadata() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Continue(event) => {
                assert_eq!(event.get_field("marker"), Some(&FieldValue::str("seen")));
            }
            _ => panic!("expected Continue"),
        }

        let stage = pipeline.metadata().get_stage("marker").unwrap();
        assert_eq!(stage.status, StageStatus::Completed);
        assert!(stage.exit_time.is_some());
    }

    #[test]
    fn test_drop_stops_pipeline_and_records_skipped() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("gate", "drops everything", always_drop));
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Drop(reason) => assert_eq!(reason, "filtered"),
            _ => panic!("expected Drop"),
        }

        // The second stage never ran because the first stage dropped the event.
        assert!(pipeline.metadata().get_stage("marker").is_none());
        let gate = pipeline.metadata().get_stage("gate").unwrap();
        assert_eq!(gate.status, StageStatus::Skipped);
    }

    #[test]
    fn test_error_stops_pipeline_and_records_failure() {
        let mut pipeline = Pipeline::new();
        pipeline.add_stage(Processor::new("boom", "always errors", always_error));
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Error(reason) => assert_eq!(reason, "boom"),
            _ => panic!("expected Error"),
        }

        assert!(pipeline.metadata().get_stage("marker").is_none());
        let boom = pipeline.metadata().get_stage("boom").unwrap();
        assert_eq!(boom.status, StageStatus::Failed);
        assert_eq!(boom.error_info, Some("boom".to_string()));
    }

    #[test]
    fn test_disabled_metadata_still_runs_stages() {
        let mut pipeline = Pipeline::with_metadata(PipelineMetadata::disabled());
        pipeline.add_stage(Processor::new("marker", "adds a marker field", add_marker));

        match pipeline.run(sample_event()) {
            ProcessResult::Continue(event) => {
                assert_eq!(event.get_field("marker"), Some(&FieldValue::str("seen")));
            }
            _ => panic!("expected Continue"),
        }
        assert!(pipeline.metadata().get_stage("marker").is_none());
    }
}
