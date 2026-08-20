use crate::event::field::Timestamp;
use std::collections::HashMap;

/// Pipeline metadata for tracking event processing metrics
/// This enables performance monitoring and bottleneck identification
#[derive(Debug, Clone)]
pub struct PipelineMetadata {
    /// Processing stages with entry and exit timestamps
    /// Key: processor name (static lifetime for zero allocation)
    /// Value: ProcessingStage with timing information
    pub(crate) stages: HashMap<&'static str, ProcessingStage>,

    /// Total processing time across all stages (cached for performance)
    pub(crate) total_processing_time: Option<std::time::Duration>,

    /// Flag to indicate if metadata collection is enabled
    pub(crate) collection_enabled: bool,
}

/// Information about a single processing stage
#[derive(Debug, Clone)]
pub struct ProcessingStage {
    /// When processing started for this stage
    pub entry_time: Timestamp,

    /// When processing completed for this stage (None if still processing)
    pub exit_time: Option<Timestamp>,

    /// Current status of this processing stage
    pub status: StageStatus,

    /// Optional error information if processing failed
    pub error_info: Option<String>,

    /// Custom metadata for this stage (e.g., record counts, bytes processed)
    pub custom_metrics: HashMap<String, MetricValue>,
}

/// Status of a processing stage
#[derive(Debug, Clone, PartialEq)]
pub enum StageStatus {
    /// Stage is currently processing
    InProgress,
    /// Stage completed successfully
    Completed,
    /// Stage failed with error
    Failed,
    /// Stage was skipped (conditional processing)
    Skipped,
}

/// Custom metric values for stages
#[derive(Debug, Clone, PartialEq)]
pub enum MetricValue {
    /// Integer counter (e.g., record count)
    Counter(i64),
    /// Floating point gauge (e.g., CPU usage percentage)
    Gauge(f64),
    /// Duration measurement (e.g., network call time)
    Duration(std::time::Duration),
    /// String label (e.g., processing mode)
    Label(String),
}

impl PipelineMetadata {
    /// Create new metadata tracker with collection enabled
    pub fn new() -> Self {
        Self {
            stages: HashMap::new(),
            total_processing_time: None,
            collection_enabled: true,
        }
    }

    /// Create metadata tracker with collection disabled (for performance)
    pub fn disabled() -> Self {
        Self {
            stages: HashMap::new(),
            total_processing_time: None,
            collection_enabled: false,
        }
    }

    /// Start processing stage with the given processor name
    /// Uses static str for zero-allocation processor identification
    pub fn start_stage(&mut self, processor_name: &'static str) {
        if !self.collection_enabled {
            return;
        }

        let stage = ProcessingStage {
            entry_time: Timestamp::now(),
            exit_time: None,
            status: StageStatus::InProgress,
            error_info: None,
            custom_metrics: HashMap::new(),
        };

        self.stages.insert(processor_name, stage);
        // Invalidate cached total time
        self.total_processing_time = None;
    }

    /// Complete processing stage successfully
    pub fn complete_stage(&mut self, processor_name: &'static str) {
        if !self.collection_enabled {
            return;
        }

        if let Some(stage) = self.stages.get_mut(processor_name) {
            stage.exit_time = Some(Timestamp::now());
            stage.status = StageStatus::Completed;
            // Invalidate cached total time
            self.total_processing_time = None;
        }
    }

    /// Mark processing stage as failed with error information
    pub fn fail_stage(&mut self, processor_name: &'static str, error: String) {
        if !self.collection_enabled {
            return;
        }

        if let Some(stage) = self.stages.get_mut(processor_name) {
            stage.exit_time = Some(Timestamp::now());
            stage.status = StageStatus::Failed;
            stage.error_info = Some(error);
            // Invalidate cached total time
            self.total_processing_time = None;
        }
    }

    /// Mark processing stage as skipped
    pub fn skip_stage(&mut self, processor_name: &'static str) {
        if !self.collection_enabled {
            return;
        }

        if let Some(stage) = self.stages.get_mut(processor_name) {
            stage.exit_time = Some(Timestamp::now());
            stage.status = StageStatus::Skipped;
        }
    }

    /// Add custom metric to a processing stage
    pub fn add_metric(
        &mut self,
        processor_name: &'static str,
        metric_name: String,
        value: MetricValue,
    ) {
        if !self.collection_enabled {
            return;
        }

        if let Some(stage) = self.stages.get_mut(processor_name) {
            stage.custom_metrics.insert(metric_name, value);
        }
    }

    /// Get processing duration for a specific stage
    pub fn get_stage_duration(&self, processor_name: &'static str) -> Option<std::time::Duration> {
        let stage = self.stages.get(processor_name)?;
        let exit_time = stage.exit_time?;

        let entry_duration = stage.entry_time.as_duration_since_epoch();
        let exit_duration = exit_time.as_duration_since_epoch();

        exit_duration.checked_sub(entry_duration)
    }

    /// Get total processing time across all completed stages
    pub fn get_total_processing_time(&mut self) -> std::time::Duration {
        if let Some(cached_time) = self.total_processing_time {
            return cached_time;
        }

        let mut total = std::time::Duration::from_secs(0);

        for stage in self.stages.values() {
            if let Some(duration) = self.calculate_stage_duration(stage) {
                total += duration;
            }
        }

        self.total_processing_time = Some(total);
        total
    }

    /// Get all processing stages
    pub fn get_stages(&self) -> &HashMap<&'static str, ProcessingStage> {
        &self.stages
    }

    /// Get a specific processing stage
    pub fn get_stage(&self, processor_name: &'static str) -> Option<&ProcessingStage> {
        self.stages.get(processor_name)
    }

    /// Check if collection is enabled
    pub fn is_enabled(&self) -> bool {
        self.collection_enabled
    }

    /// Enable metadata collection
    pub fn enable(&mut self) {
        self.collection_enabled = true;
    }

    /// Disable metadata collection (for performance)
    pub fn disable(&mut self) {
        self.collection_enabled = false;
    }

    /// Get summary statistics for performance analysis
    pub fn get_performance_summary(&mut self) -> PerformanceSummary {
        let mut completed_stages = 0;
        let mut failed_stages = 0;
        let mut skipped_stages = 0;
        let mut in_progress_stages = 0;
        let mut slowest_stage: Option<(&'static str, std::time::Duration)> = None;

        for (name, stage) in &self.stages {
            match stage.status {
                StageStatus::Completed => completed_stages += 1,
                StageStatus::Failed => failed_stages += 1,
                StageStatus::Skipped => skipped_stages += 1,
                StageStatus::InProgress => in_progress_stages += 1,
            }

            if let Some(duration) = self.calculate_stage_duration(stage) {
                if let Some((_, current_max)) = slowest_stage {
                    if duration > current_max {
                        slowest_stage = Some((name, duration));
                    }
                } else {
                    slowest_stage = Some((name, duration));
                }
            }
        }

        PerformanceSummary {
            total_stages: self.stages.len(),
            completed_stages,
            failed_stages,
            skipped_stages,
            in_progress_stages,
            total_processing_time: self.get_total_processing_time(),
            slowest_stage,
        }
    }

    /// Helper to calculate duration for a stage
    fn calculate_stage_duration(&self, stage: &ProcessingStage) -> Option<std::time::Duration> {
        let exit_time = stage.exit_time?;
        let entry_duration = stage.entry_time.as_duration_since_epoch();
        let exit_duration = exit_time.as_duration_since_epoch();
        exit_duration.checked_sub(entry_duration)
    }
}

/// Performance summary for pipeline analysis
#[derive(Debug, Clone)]
pub struct PerformanceSummary {
    pub total_stages: usize,
    pub completed_stages: usize,
    pub failed_stages: usize,
    pub skipped_stages: usize,
    pub in_progress_stages: usize,
    pub total_processing_time: std::time::Duration,
    pub slowest_stage: Option<(&'static str, std::time::Duration)>,
}

impl Default for PipelineMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricValue {
    /// Create a counter metric
    pub fn counter(value: i64) -> Self {
        MetricValue::Counter(value)
    }

    /// Create a gauge metric
    pub fn gauge(value: f64) -> Self {
        MetricValue::Gauge(value)
    }

    /// Create a duration metric
    pub fn duration(value: std::time::Duration) -> Self {
        MetricValue::Duration(value)
    }

    /// Create a label metric
    pub fn label<S: Into<String>>(value: S) -> Self {
        MetricValue::Label(value.into())
    }

    /// Get the metric value as a string for display
    pub fn as_string(&self) -> String {
        match self {
            MetricValue::Counter(n) => n.to_string(),
            MetricValue::Gauge(f) => format!("{:.2}", f),
            MetricValue::Duration(d) => format!("{:.2?}", d),
            MetricValue::Label(s) => s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    #[test]
    fn test_metadata_creation() {
        let metadata = PipelineMetadata::new();
        assert!(metadata.is_enabled());
        assert_eq!(metadata.get_stages().len(), 0);

        let disabled_metadata = PipelineMetadata::disabled();
        assert!(!disabled_metadata.is_enabled());
    }

    #[test]
    fn test_stage_lifecycle() {
        let mut metadata = PipelineMetadata::new();

        // Start a stage
        metadata.start_stage("parser");
        assert_eq!(metadata.get_stages().len(), 1);

        let stage = metadata.get_stage("parser").unwrap();
        assert_eq!(stage.status, StageStatus::InProgress);
        assert!(stage.exit_time.is_none());

        // Complete the stage
        metadata.complete_stage("parser");

        let stage = metadata.get_stage("parser").unwrap();
        assert_eq!(stage.status, StageStatus::Completed);
        assert!(stage.exit_time.is_some());
    }

    #[test]
    fn test_stage_failure() {
        let mut metadata = PipelineMetadata::new();

        metadata.start_stage("validator");
        metadata.fail_stage("validator", "Invalid format".to_string());

        let stage = metadata.get_stage("validator").unwrap();
        assert_eq!(stage.status, StageStatus::Failed);
        assert_eq!(stage.error_info, Some("Invalid format".to_string()));
    }

    #[test]
    fn test_custom_metrics() {
        let mut metadata = PipelineMetadata::new();

        metadata.start_stage("enricher");
        metadata.add_metric(
            "enricher",
            "records_processed".to_string(),
            MetricValue::counter(150),
        );
        metadata.add_metric(
            "enricher",
            "cpu_usage".to_string(),
            MetricValue::gauge(45.7),
        );
        metadata.add_metric("enricher", "mode".to_string(), MetricValue::label("fast"));

        let stage = metadata.get_stage("enricher").unwrap();
        assert_eq!(stage.custom_metrics.len(), 3);

        if let Some(MetricValue::Counter(count)) = stage.custom_metrics.get("records_processed") {
            assert_eq!(*count, 150);
        }
    }

    #[test]
    fn test_performance_summary() {
        let mut metadata = PipelineMetadata::new();

        // Simulate some processing stages
        metadata.start_stage("parser");
        metadata.complete_stage("parser");

        metadata.start_stage("validator");
        metadata.fail_stage("validator", "Error".to_string());

        metadata.start_stage("enricher");
        metadata.skip_stage("enricher");

        let summary = metadata.get_performance_summary();
        assert_eq!(summary.total_stages, 3);
        assert_eq!(summary.completed_stages, 1);
        assert_eq!(summary.failed_stages, 1);
        assert_eq!(summary.skipped_stages, 1);
        assert_eq!(summary.in_progress_stages, 0);
    }

    #[test]
    fn test_disabled_metadata() {
        let mut metadata = PipelineMetadata::disabled();

        // Operations should be no-ops when disabled
        metadata.start_stage("parser");
        metadata.complete_stage("parser");
        metadata.add_metric("parser", "test".to_string(), MetricValue::counter(1));

        assert_eq!(metadata.get_stages().len(), 0);
    }

    #[test]
    fn test_metric_value_display() {
        let counter = MetricValue::counter(42);
        let gauge = MetricValue::gauge(99.99);
        let duration = MetricValue::duration(Duration::from_millis(150));
        let label = MetricValue::label("production");

        assert_eq!(counter.as_string(), "42");
        assert_eq!(gauge.as_string(), "99.99");
        assert_eq!(label.as_string(), "production");
        assert!(duration.as_string().contains("150"));
    }
}
