//! Core traits and types for the enrichment system
//!
//! This module provides the foundational abstractions for the SIEM enrichment framework:
//! - Type-safe dataset key definitions with compile-time guarantees
//! - Runtime type erasure for dynamic dataset management
//! - Error handling for enrichment operations
//!
//! # Architecture
//!
//! The enrichment system uses a dual-level type system:
//! 1. **Compile-time safety** via `DatasetKey` trait for known dataset types
//! 2. **Runtime flexibility** via `AnyDataset` trait for dynamic operations
//!
//! This allows both type-safe usage in application code and flexible
//! runtime management in the enrichment registry and manager.

use std::any::Any;

/// Trait for strongly-typed dataset keys that provide compile-time type safety
///
/// This trait defines the association between a key type and its corresponding
/// dataset, key, and value types. It ensures type safety when accessing datasets
/// while enabling runtime identification via the NAME constant.
///
/// # Type Parameters
///
/// * `Dataset` - The concrete dataset implementation (e.g., `MapDataset<K,V>`)
/// * `Key` - The type used to look up values (e.g., `Ip`, `Text`)  
/// * `Value` - The enrichment data type (e.g., `GeoIp`, `ThreatInfo`)
///
/// # Example
///
/// ```rust,no_compile,no_run
/// pub struct GeoIpKey;
///
/// impl DatasetKey for GeoIpKey {
///     type Dataset = MapDataset<Ip, GeoIp>;
///     type Key = Ip;
///     type Value = GeoIp;
///     const NAME: &'static str = "geoip";
/// }
/// ```
pub trait DatasetKey: 'static + Send + Sync {
    /// The dataset type associated with this key
    ///
    /// This should be a concrete implementation like `MapDataset<K,V>` or
    /// `NetworkTypedDataset<V,U>` that can store and retrieve the enrichment data.
    type Dataset: AnyDataset + 'static;

    /// The key type used to index into the dataset
    ///
    /// Common key types include:
    /// - `Ip` for IP address lookups (GeoIP, threat intel)
    /// - `Text` for string-based lookups (usernames, hostnames)
    /// - Custom types for specialized datasets
    type Key: Clone + Send + Sync + 'static;

    /// The value type stored in the dataset
    ///
    /// This represents the enrichment information returned by lookups:
    /// - `GeoIp` for geographic IP information
    /// - `ThreatInfo` for threat intelligence data
    /// - `AssetInfo` for asset management data
    /// - Custom types for domain-specific enrichment
    type Value: Clone + Send + Sync + 'static;

    /// Unique name for this dataset type
    ///
    /// This identifier is used for:
    /// - Runtime dataset registration and lookup
    /// - Configuration and logging
    /// - Persistence layer identification
    /// - Inter-process communication
    ///
    /// Should be a stable, descriptive name like "geoip", "threat_ip", etc.
    const NAME: &'static str;
}

/// Type-erased trait for datasets to enable runtime storage and manipulation
///
/// This trait provides a uniform interface for all dataset types, enabling
/// the enrichment system to store and manipulate datasets of different types
/// in collections without knowing their concrete types at compile time.
///
/// # Design Principles
///
/// * **Immutability** - Updates return new instances rather than modifying in-place
/// * **Type Safety** - Updates are type-checked via downcasting at runtime  
/// * **Performance** - Batch updates minimize overhead for multiple operations
/// * **Flexibility** - Any dataset type can implement this trait
///
/// # Update Semantics
///
/// All update operations return new dataset instances, following functional
/// programming principles. This ensures thread safety and enables features
/// like rollback, audit trails, and concurrent access patterns.
///
/// # Implementation Notes
///
/// Implementors should:
/// - Validate update types via downcasting before application
/// - Return unchanged datasets for incompatible update types
/// - Optimize batch updates to avoid intermediate allocations
/// - Maintain type identity through the `type_name()` method
pub trait AnyDataset: Send + Sync {
    /// Apply an update to the dataset, returning a new dataset instance
    ///
    /// This method attempts to downcast the type-erased update to the
    /// dataset's expected update type. If successful, it applies the update
    /// and returns a new dataset instance. If the update type doesn't match,
    /// it should return an unchanged copy of the dataset.
    ///
    /// # Parameters
    ///
    /// * `update` - A type-erased update that should be downcast to the
    ///   dataset's expected update type (e.g., `DatasetUpdate<K,V>`)
    ///
    /// # Returns
    ///
    /// A new dataset instance with the update applied, or an unchanged copy
    /// if the update type was incompatible.
    ///
    /// # Thread Safety
    ///
    /// This method is safe to call concurrently as it doesn't modify the
    /// original dataset instance.
    fn apply_update(&self, update: Box<dyn Any + Send>) -> Box<dyn AnyDataset>;

    /// Apply multiple updates at once, more efficient than individual updates
    ///
    /// Batch processing reduces allocation overhead and allows for optimizations
    /// like bulk operations on underlying storage. Updates are applied in order,
    /// with each subsequent update operating on the result of the previous one.
    ///
    /// # Parameters
    ///
    /// * `updates` - A vector of type-erased updates to apply sequentially
    ///
    /// # Returns
    ///
    /// A new dataset instance with all compatible updates applied.
    /// Incompatible updates are silently ignored.
    ///
    /// # Performance Notes
    ///
    /// Implementations should optimize this for better performance than
    /// calling `apply_update()` repeatedly, potentially by:
    /// - Batching operations on underlying storage
    /// - Avoiding intermediate allocations  
    /// - Combining multiple operations of the same type
    fn apply_batch_updates(&self, updates: Vec<Box<dyn Any + Send>>) -> Box<dyn AnyDataset>;

    /// Get a reference to the dataset as Any for downcasting
    ///
    /// This enables type recovery from trait objects, allowing code that
    /// knows the concrete dataset type to access type-specific methods.
    ///
    /// # Usage
    ///
    /// ```rust,no_compile,no_run
    /// if let Some(typed_dataset) = any_dataset.as_any()
    ///     .downcast_ref::<MapDataset<Ip, GeoIp>>() {
    ///     // Access typed methods
    ///     let geo_data = typed_dataset.get(&ip_addr);
    /// }
    /// ```
    fn as_any(&self) -> &dyn Any;

    /// Clone the dataset into a Box
    ///
    /// Creates a new boxed instance of the dataset. This is required because
    /// trait objects don't automatically implement Clone, even if the
    /// concrete type does.
    ///
    /// # Returns
    ///
    /// A new boxed dataset instance that is a clone of the current one.
    fn clone_box(&self) -> Box<dyn AnyDataset>;

    /// Get the name of this dataset type
    ///
    /// Returns a string identifier for the dataset type, typically matching
    /// the NAME constant from the corresponding DatasetKey implementation.
    ///
    /// This is used for:
    /// - Debugging and logging  
    /// - Runtime type identification
    /// - Serialization metadata
    /// - Configuration validation
    ///
    /// # Returns
    ///
    /// A static string identifying the dataset type (e.g., "geoip", "threat_ip").
    fn type_name(&self) -> &'static str;
}

/// Errors that can occur during enrichment operations
///
/// This enum represents all possible error conditions in the enrichment system,
/// from data serialization failures to missing datasets and invalid keys.
///
/// # Error Categories
///
/// * **Data Errors** - Serialization/deserialization failures
/// * **Storage Errors** - IO and persistence layer failures  
/// * **Logic Errors** - Missing datasets and invalid keys
///
/// # Error Handling Strategy
///
/// The enrichment system uses Result types for all fallible operations,
/// allowing callers to handle errors appropriately. Common patterns include:
/// - Logging and continuing with default values
/// - Falling back to alternative data sources
/// - Propagating critical errors to stop processing
///
/// # Example
///
/// ```rust,no_compile,no_run
/// match registry.get_dataset("geoip") {
///     Ok(dataset) => { /* use dataset */ },
///     Err(EnrichmentError::DatasetNotFound(name)) => {
///         log::warn!("GeoIP dataset not available: {}", name);
///         // Continue with limited functionality
///     },
///     Err(e) => return Err(e), // Propagate other errors
/// }
/// ```
#[derive(Debug)]
pub enum EnrichmentError {
    /// Failed to serialize data for storage or transmission
    ///
    /// This occurs when dataset contents or updates cannot be converted
    /// to the required storage format (JSON, binary, etc.). Common causes:
    /// - Invalid UTF-8 sequences in text fields
    /// - Circular references in data structures
    /// - Exceeding serialization limits
    Serialization(String),

    /// Failed to deserialize data from storage or transmission
    ///
    /// This occurs when reading stored data that doesn't match the expected
    /// format or schema. Common causes:
    /// - Schema evolution breaking backward compatibility
    /// - Corrupted storage files
    /// - Version mismatches between writer and reader
    Deserialization(String),

    /// IO error during persistence operations
    ///
    /// Wraps standard IO errors that occur during:
    /// - Reading/writing dataset files
    /// - Network operations for remote datasets
    /// - Database connection issues
    /// - Permission or disk space problems
    Io(std::io::Error),

    /// Dataset not found in the registry
    ///
    /// Occurs when requesting a dataset that hasn't been registered
    /// or has been removed. The string contains the dataset name that
    /// was requested.
    DatasetNotFound(String),

    /// Invalid key provided for dataset operations
    ///
    /// Occurs when:
    /// - Key format doesn't match dataset expectations
    /// - Key contains invalid characters or values
    /// - Key is outside the valid range for the dataset
    InvalidKey(String),
}

impl std::fmt::Display for EnrichmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrichmentError::Serialization(msg) => write!(f, "Serialization failed: {}", msg),
            EnrichmentError::Deserialization(msg) => write!(f, "Deserialization failed: {}", msg),
            EnrichmentError::Io(err) => write!(f, "IO error: {}", err),
            EnrichmentError::DatasetNotFound(name) => write!(f, "Dataset not found: {}", name),
            EnrichmentError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
        }
    }
}

impl std::error::Error for EnrichmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EnrichmentError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EnrichmentError {
    fn from(err: std::io::Error) -> Self {
        EnrichmentError::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;
    use std::error::Error;

    // Test dataset implementation for testing
    #[derive(Debug, Clone)]
    struct TestDataset {
        #[allow(dead_code)]
        data: HashMap<String, String>,
    }

    impl AnyDataset for TestDataset {
        fn apply_update(&self, _update: Box<dyn Any + Send>) -> Box<dyn AnyDataset> {
            // For testing, just return a clone
            Box::new(self.clone())
        }

        fn apply_batch_updates(&self, _updates: Vec<Box<dyn Any + Send>>) -> Box<dyn AnyDataset> {
            // For testing, just return a clone
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn clone_box(&self) -> Box<dyn AnyDataset> {
            Box::new(self.clone())
        }

        fn type_name(&self) -> &'static str {
            "TestDataset"
        }
    }

    // Test dataset key implementation
    struct TestKey;

    impl DatasetKey for TestKey {
        type Dataset = TestDataset;
        type Key = String;
        type Value = String;
        const NAME: &'static str = "test";
    }

    #[test]
    fn test_dataset_key_name() {
        assert_eq!(TestKey::NAME, "test");
    }

    #[test]
    fn test_any_dataset_type_name() {
        let dataset = TestDataset {
            data: HashMap::new(),
        };

        assert_eq!(dataset.type_name(), "TestDataset");
    }

    #[test]
    fn test_any_dataset_as_any() {
        let dataset = TestDataset {
            data: HashMap::new(),
        };

        // Test downcasting
        let any_dataset: &dyn AnyDataset = &dataset;
        let recovered = any_dataset.as_any().downcast_ref::<TestDataset>();
        assert!(recovered.is_some());
    }

    #[test]
    fn test_any_dataset_clone_box() {
        let dataset = TestDataset {
            data: HashMap::new(),
        };

        let cloned = dataset.clone_box();
        assert_eq!(cloned.type_name(), "TestDataset");
    }

    #[test]
    fn test_enrichment_error_display() {
        let err = EnrichmentError::DatasetNotFound("test_dataset".to_string());
        assert_eq!(err.to_string(), "Dataset not found: test_dataset");

        let err = EnrichmentError::Serialization("invalid format".to_string());
        assert_eq!(err.to_string(), "Serialization failed: invalid format");

        let err = EnrichmentError::Deserialization("corrupt data".to_string());
        assert_eq!(err.to_string(), "Deserialization failed: corrupt data");

        let err = EnrichmentError::InvalidKey("malformed key".to_string());
        assert_eq!(err.to_string(), "Invalid key: malformed key");
    }

    #[test]
    fn test_enrichment_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let enrichment_err: EnrichmentError = io_err.into();

        match enrichment_err {
            EnrichmentError::Io(_) => (), // Expected
            _ => panic!("Should convert to IO error"),
        }
    }

    #[test]
    fn test_enrichment_error_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let enrichment_err = EnrichmentError::Io(io_err);

        assert!(enrichment_err.source().is_some());

        let other_err = EnrichmentError::DatasetNotFound("test".to_string());
        assert!(other_err.source().is_none());
    }
}
