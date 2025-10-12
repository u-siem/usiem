//! Enrichment manager with dataset tracking and configurable merge policies

use crate::event::field::{Ip, Text};
use crate::processing::enrichment::core::{AnyDataset, EnrichmentError};
use crate::processing::enrichment::dataset::MapDataset;
use crate::processing::enrichment::registry::EnrichmentRegistry;
use crate::processing::enrichment::types::{AssetInfo, GeoIp, ThreatInfo, UserProfile};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for enrichment manager behavior
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// How frequently to merge dataset changes (per dataset type)
    pub merge_intervals: std::collections::HashMap<String, Duration>,
    /// Default merge interval for datasets not specifically configured
    pub default_merge_interval: Duration,
    /// Datasets that should not be persisted to disk
    pub ephemeral_datasets: std::collections::HashSet<String>,
    /// Maximum number of queued updates before forcing a merge
    pub max_queued_updates: usize,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            merge_intervals: std::collections::HashMap::new(),
            default_merge_interval: Duration::from_secs(30),
            ephemeral_datasets: std::collections::HashSet::new(),
            max_queued_updates: 1000,
        }
    }
}

/// Message sent to orchestrator containing updated dataset
#[derive(Clone)]
pub struct DatasetUpdateMessage {
    /// Name of the dataset that was updated
    pub dataset_name: &'static str,
    /// The updated dataset
    pub updated_dataset: Arc<dyn AnyDataset>,
    /// Timestamp when the update was processed
    pub update_timestamp: Instant,
}

/// Trait for managing datasets with different types in a unified way
pub trait ManagedDatasetTrait: Send + Sync {
    /// Get the dataset name
    fn name(&self) -> &'static str;
    /// Poll for updates and queue them
    fn poll_updates(&mut self) -> Result<(), EnrichmentError>;
    /// Check if this dataset should be merged based on config
    fn should_merge(&self, config: &ManagerConfig) -> bool;
    /// Merge queued updates and send to orchestrator
    fn merge_updates(&mut self) -> Result<(), EnrichmentError>;
    /// Get the number of queued updates
    fn queue_size(&self) -> usize;
    /// Get last merge time
    fn last_merge(&self) -> Instant;
    /// Check if dataset is ephemeral
    fn is_ephemeral(&self) -> bool;
    /// Set ephemeral flag
    fn set_ephemeral(&mut self, ephemeral: bool);
}

/// Tracks a managed dataset with its update queue and merge state
pub struct ManagedDataset<K, V>
where
    K: Clone + Send + Sync + std::cmp::Eq + std::hash::Hash + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Name of the dataset
    pub name: &'static str,
    /// Current strongly-typed dataset
    pub current_dataset: Arc<MapDataset<K, V>>,
    /// Queue of pending updates to be merged
    pub queued_updates: VecDeque<crate::processing::enrichment::dataset::DatasetUpdate<K, V>>,
    /// Last time this dataset was merged
    pub last_merge: Instant,
    /// Receiver for updates from external sources (wrapped in Arc<Mutex> for thread safety)
    pub update_receiver: Arc<
        std::sync::Mutex<
            std::sync::mpsc::Receiver<crate::processing::enrichment::dataset::DatasetUpdate<K, V>>,
        >,
    >,
    /// Sender to orchestrator for broadcasting updated datasets
    pub orchestrator_sender: std::sync::mpsc::Sender<DatasetUpdateMessage>,
    /// Whether this dataset should be persisted
    pub is_ephemeral: bool,
}

impl<K, V> ManagedDatasetTrait for ManagedDataset<K, V>
where
    K: Clone + Send + Sync + std::cmp::Eq + std::hash::Hash + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn poll_updates(&mut self) -> Result<(), EnrichmentError> {
        use std::sync::mpsc::TryRecvError;

        let receiver = self
            .update_receiver
            .lock()
            .map_err(|_| EnrichmentError::DatasetNotFound("Receiver lock poisoned".to_string()))?;

        loop {
            match receiver.try_recv() {
                Ok(update) => {
                    self.queued_updates.push_back(update);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(EnrichmentError::DatasetNotFound(
                        "Dataset sender disconnected".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn should_merge(&self, config: &ManagerConfig) -> bool {
        let now = Instant::now();
        let merge_interval = config
            .merge_intervals
            .get(self.name)
            .cloned()
            .unwrap_or(config.default_merge_interval);

        now.duration_since(self.last_merge) >= merge_interval
            || self.queued_updates.len() >= config.max_queued_updates
    }

    fn merge_updates(&mut self) -> Result<(), EnrichmentError> {
        if self.queued_updates.is_empty() {
            return Ok(());
        }

        // Apply all queued updates to create new dataset
        let updates: Vec<_> = self.queued_updates.drain(..).collect();
        let new_dataset = self.current_dataset.apply_batch_updates_typed(updates);

        // Update current dataset
        self.current_dataset = Arc::new(new_dataset.clone());
        self.last_merge = Instant::now();

        // Send updated dataset to orchestrator
        let message = DatasetUpdateMessage {
            dataset_name: self.name,
            updated_dataset: Arc::new(new_dataset) as Arc<dyn AnyDataset>,
            update_timestamp: self.last_merge,
        };

        self.orchestrator_sender.send(message).map_err(|_| {
            EnrichmentError::DatasetNotFound("Orchestrator disconnected".to_string())
        })?;

        Ok(())
    }

    fn queue_size(&self) -> usize {
        self.queued_updates.len()
    }

    fn last_merge(&self) -> Instant {
        self.last_merge
    }

    fn is_ephemeral(&self) -> bool {
        self.is_ephemeral
    }

    fn set_ephemeral(&mut self, ephemeral: bool) {
        self.is_ephemeral = ephemeral;
    }
}

/// Builder for creating datasets and setting up the registry
pub struct DatasetBuilder {
    registry: EnrichmentRegistry,
    managed_datasets: Vec<Box<dyn ManagedDatasetTrait>>,
    orchestrator_sender: std::sync::mpsc::Sender<DatasetUpdateMessage>,
}

impl DatasetBuilder {
    /// Create a new dataset builder
    pub fn new(orchestrator_sender: std::sync::mpsc::Sender<DatasetUpdateMessage>) -> Self {
        Self {
            registry: EnrichmentRegistry::new(),
            managed_datasets: Vec::new(),
            orchestrator_sender,
        }
    }

    /// Register a new typed dataset with its receiver
    pub fn register_typed_dataset<K, V>(
        mut self,
        name: &'static str,
        initial_data: Option<std::collections::HashMap<K, V>>,
    ) -> Self
    where
        K: Clone + Send + Sync + std::cmp::Eq + std::hash::Hash + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let (dataset, receiver) = if let Some(data) = initial_data {
            let (_empty_dataset, receiver) = MapDataset::new();
            let dataset = MapDataset::with_data(data);
            (dataset, receiver)
        } else {
            MapDataset::new()
        };

        // Create managed dataset entry
        let managed_dataset = ManagedDataset {
            name,
            current_dataset: Arc::new(dataset),
            queued_updates: VecDeque::new(),
            last_merge: Instant::now(),
            update_receiver: Arc::new(std::sync::Mutex::new(receiver)),
            orchestrator_sender: self.orchestrator_sender.clone(),
            is_ephemeral: false, // Will be set by config
        };

        self.managed_datasets.push(Box::new(managed_dataset));
        self
    }

    /// Convenience method to register GeoIP dataset
    pub fn with_geoip_dataset(self, data: Option<std::collections::HashMap<Ip, GeoIp>>) -> Self {
        self.register_typed_dataset("geoip", data)
    }

    /// Convenience method to register Threat Intelligence dataset
    pub fn with_threat_dataset(
        self,
        data: Option<std::collections::HashMap<Ip, ThreatInfo>>,
    ) -> Self {
        self.register_typed_dataset("threat_ip", data)
    }

    /// Convenience method to register Asset Information dataset
    pub fn with_asset_dataset(
        self,
        data: Option<std::collections::HashMap<Text, AssetInfo>>,
    ) -> Self {
        self.register_typed_dataset("assets", data)
    }

    /// Convenience method to register User Profile dataset
    pub fn with_user_dataset(
        self,
        data: Option<std::collections::HashMap<Text, UserProfile>>,
    ) -> Self {
        self.register_typed_dataset("users", data)
    }

    /// Complete registration and create manager
    pub fn build(self, config: ManagerConfig) -> EnrichmentManager {
        EnrichmentManager::from_builder(self, config)
    }
}

/// Manager for processing dataset updates with configurable merge policies
pub struct EnrichmentManager {
    /// Configuration for manager behavior
    config: ManagerConfig,
    /// All managed datasets with their update queues
    managed_datasets: Vec<Box<dyn ManagedDatasetTrait>>,
    /// The current registry (consumed from initial setup)
    registry: EnrichmentRegistry,
}

impl EnrichmentManager {
    /// Create new enrichment manager from a dataset builder
    pub fn from_builder(mut builder: DatasetBuilder, config: ManagerConfig) -> Self {
        // Update ephemeral flags from config
        for managed_dataset in &mut builder.managed_datasets {
            if config.ephemeral_datasets.contains(managed_dataset.name()) {
                managed_dataset.set_ephemeral(true);
            }
        }

        Self {
            config,
            managed_datasets: builder.managed_datasets,
            registry: builder.registry,
        }
    }

    /// Create a new dataset builder for building the manager
    pub fn builder(
        orchestrator_sender: std::sync::mpsc::Sender<DatasetUpdateMessage>,
    ) -> DatasetBuilder {
        DatasetBuilder::new(orchestrator_sender)
    }

    /// Get current registry (lock-free read access)
    pub fn registry(&mut self) -> &mut EnrichmentRegistry {
        &mut self.registry
    }

    /// Run the main processing loop to handle updates from all datasets
    /// This is a blocking operation that processes updates as they arrive
    pub fn run_processing_loop(&mut self) -> Result<(), EnrichmentError> {
        use std::thread;
        use std::time::Duration as StdDuration;

        // Process updates in a loop
        loop {
            // Collect all pending updates from receivers
            self.collect_all_updates()?;

            // Process pending merges
            self.process_pending_merges()?;

            // Sleep briefly to avoid busy waiting
            thread::sleep(StdDuration::from_millis(10));
        }
    }

    /// Process pending merges based on timing and queue size
    pub fn process_pending_merges(&mut self) -> Result<(), EnrichmentError> {
        for managed_dataset in &mut self.managed_datasets {
            // Check if this dataset should be merged
            if managed_dataset.should_merge(&self.config) && managed_dataset.queue_size() > 0 {
                managed_dataset.merge_updates()?;
            }
        }

        Ok(())
    }

    /// Collect updates from all dataset receivers (non-blocking)
    pub fn collect_all_updates(&mut self) -> Result<(), EnrichmentError> {
        for managed_dataset in &mut self.managed_datasets {
            managed_dataset.poll_updates()?;
        }
        Ok(())
    }

    /// Get a dataset sender for external updates
    pub fn get_dataset_handle<K, V>(&self, _dataset_name: &str) -> Option<MapDataset<K, V>>
    where
        K: Clone + Send + Sync + std::cmp::Eq + std::hash::Hash + 'static,
        V: Clone + Send + Sync + 'static,
    {
        // TODO: This method needs to be redesigned with the new trait-based approach
        // For now, return None as we need access to the concrete dataset type
        None
    }

    /// Force merge all datasets regardless of timing
    pub fn force_merge_all(&mut self) -> Result<(), EnrichmentError> {
        for managed_dataset in &mut self.managed_datasets {
            if managed_dataset.queue_size() > 0 {
                managed_dataset.merge_updates()?;
            }
        }
        Ok(())
    }

    /// Get statistics about managed datasets
    pub fn get_statistics(&self) -> Vec<DatasetStatistics> {
        self.managed_datasets
            .iter()
            .map(|dataset| DatasetStatistics {
                name: dataset.name(),
                queued_updates: dataset.queue_size(),
                last_merge: dataset.last_merge(),
                is_ephemeral: dataset.is_ephemeral(),
            })
            .collect()
    }
}

/// Statistics for a managed dataset
#[derive(Debug, Clone)]
pub struct DatasetStatistics {
    pub name: &'static str,
    pub queued_updates: usize,
    pub last_merge: Instant,
    pub is_ephemeral: bool,
}

impl EnrichmentManager {
    /// Example of how to set up the enrichment manager with datasets
    pub fn create_example()
    -> Result<(Self, std::sync::mpsc::Receiver<DatasetUpdateMessage>), EnrichmentError> {
        use std::collections::HashMap;

        // Create configuration
        let mut config = ManagerConfig::default();
        config.ephemeral_datasets.insert("temp_data".to_string());

        // Create orchestrator channel for receiving dataset updates
        let (orchestrator_sender, orchestrator_receiver) = std::sync::mpsc::channel();

        // Create manager with datasets
        let manager = EnrichmentManager::builder(orchestrator_sender)
            .with_geoip_dataset(None) // Empty GeoIP dataset
            .with_threat_dataset(None) // Empty Threat dataset
            .with_asset_dataset(Some({
                let mut assets = HashMap::new();
                assets.insert(
                    Text::from("server01"),
                    AssetInfo {
                        asset_type: Text::from("server"),
                        owner: Some(Text::from("ops-team")),
                        criticality: 5,
                        location: Some(Text::from("datacenter1")),
                        tags: vec![Text::from("production"), Text::from("web-server")],
                    },
                );
                assets
            })) // Asset dataset with sample data
            .with_user_dataset(None) // Empty User dataset
            .build(config);

        Ok((manager, orchestrator_receiver))
    }
}
