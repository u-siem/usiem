//! Lock-free enrichment registry for managing strongly-typed datasets

use crate::processing::enrichment::core::{AnyDataset, DatasetKey};
use std::collections::HashMap;

/// Lock-free registry for managing multiple strongly-typed datasets
#[derive(Clone)]
pub struct EnrichmentRegistry {
    /// Immutable datasets
    datasets: HashMap<&'static str, std::sync::Arc<dyn AnyDataset>>,
}

impl Default for EnrichmentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EnrichmentRegistry {
    /// Create a new enrichment registry
    pub fn new() -> Self {
        Self {
            datasets: HashMap::new(),
        }
    }

    /// Register a new dataset with type safety (used during initialization)
    pub fn register<K: DatasetKey>(&mut self, dataset: K::Dataset) {
        self.datasets.insert(K::NAME, std::sync::Arc::new(dataset));
    }

    /// Get a strongly-typed dataset by key type
    pub fn get<K: DatasetKey>(&self) -> Option<&K::Dataset> {
        self.datasets
            .get(K::NAME)?
            .as_any()
            .downcast_ref::<K::Dataset>()
    }

    /// Get dataset names
    pub fn dataset_names(&self) -> Vec<&'static str> {
        self.datasets.keys().copied().collect()
    }

    /// Get all datasets (used by manager to consume registry)
    pub fn get_datasets(self) -> HashMap<&'static str, std::sync::Arc<dyn AnyDataset>> {
        self.datasets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::Text;
    use crate::processing::enrichment::dataset::MapDataset;

    // Test key implementation
    struct TestDatasetKey;

    impl DatasetKey for TestDatasetKey {
        type Dataset = MapDataset<Text, String>;
        type Key = Text;
        type Value = String;
        const NAME: &'static str = "test_dataset";
    }

    #[test]
    fn test_registry_new() {
        let registry = EnrichmentRegistry::new();
        assert!(registry.dataset_names().is_empty());
    }

    #[test]
    fn test_registry_register() {
        let mut registry = EnrichmentRegistry::new();

        let (dataset, _receiver) = MapDataset::<Text, String>::new();

        registry.register::<TestDatasetKey>(dataset);

        let names = registry.dataset_names();
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"test_dataset"));
    }

    #[test]
    fn test_registry_multiple_datasets() {
        let mut registry = EnrichmentRegistry::new();

        // Register first dataset
        let (dataset1, _receiver1) = MapDataset::<Text, String>::new();
        registry.register::<TestDatasetKey>(dataset1);

        // Create second key type for testing
        struct SecondTestKey;
        impl DatasetKey for SecondTestKey {
            type Dataset = MapDataset<Text, i32>;
            type Key = Text;
            type Value = i32;
            const NAME: &'static str = "second_dataset";
        }

        let (dataset2, _receiver2) = MapDataset::<Text, i32>::new();
        registry.register::<SecondTestKey>(dataset2);

        let names = registry.dataset_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"test_dataset"));
        assert!(names.contains(&"second_dataset"));
    }

    #[test]
    fn test_registry_get_datasets() {
        let mut registry = EnrichmentRegistry::new();

        let (dataset, _receiver) = MapDataset::<Text, String>::new();
        registry.register::<TestDatasetKey>(dataset);

        let datasets = registry.get_datasets();
        assert_eq!(datasets.len(), 1);
        assert!(datasets.contains_key("test_dataset"));

        let retrieved_dataset = datasets.get("test_dataset").unwrap();
        assert_eq!(
            retrieved_dataset.type_name(),
            std::any::type_name::<MapDataset<Text, String>>()
        );
    }

    #[test]
    fn test_registry_overwrite() {
        let mut registry = EnrichmentRegistry::new();

        // Register first dataset
        let (dataset1, _receiver1) = MapDataset::<Text, String>::new();
        registry.register::<TestDatasetKey>(dataset1);

        // Register another dataset with same key (should overwrite)
        let (dataset2, _receiver2) = MapDataset::<Text, String>::new();
        registry.register::<TestDatasetKey>(dataset2);

        let names = registry.dataset_names();
        assert_eq!(names.len(), 1); // Should still be 1, not 2
        assert!(names.contains(&"test_dataset"));
    }
}
