//! Strongly-typed enrichment system for SIEM event processing
//!
//! This module provides a comprehensive framework for enriching security events with
//! contextual information from various data sources. It supports both simple key-value
//! lookups and complex network-based queries with type safety, concurrency, and
//! pluggable external data providers.
//!
//! # Architecture Overview
//!
//! The enrichment system is built around several key components:
//!
//! * **[Core Abstractions](core)** - Type-safe interfaces and error handling
//! * **[Dataset Implementations](dataset)** - Storage and update mechanisms  
//! * **[CIDR tables](cidr)** - In-memory longest-prefix-match [`CidrDataset`]
//! * **[Standard Types](types)** - Common enrichment data structures
//! * **[Provider Interfaces](providers)** - External library integration points
//! * **[Registry](registry)** - Dataset discovery and management
//! * **[Manager](manager)** - Advanced dataset lifecycle and orchestration
//! * **[Keys](keys)** - Strongly-typed dataset key definitions
//!
//! # Key Features
//!
//! * **Type Safety** - Compile-time guarantees for dataset operations
//! * **Concurrency** - Lock-free, immutable data structures for high performance
//! * **Pluggable Providers** - External libraries can implement standard interfaces
//! * **Network-Aware** - Built-in support for IP network range lookups
//! * **Update Channels** - Asynchronous dataset updates without blocking readers
//! * **Batch Processing** - Efficient bulk update operations
//! * **Monitoring** - Built-in statistics and health checking
//!
//! # Usage Patterns
//!
//! ## Simple Key-Value Enrichment
//!
//! ```rust,no_compile,no_run
//! use usiem::processing::enrichment::*;
//!
//! // Create a dataset for user information
//! let (user_dataset, _receiver) = MapDataset::<Text, UserProfile>::new();
//!
//! // Look up user information
//! if let Some(user_info) = user_dataset.get(&username) {
//!     println!("User {} is in department {}",
//!              username, user_info.department.as_ref().unwrap());
//! }
//! ```
//!
//! ## Network-Based Enrichment
//!
//! ```rust,no_compile,no_run
//! // External library provides GeoIP implementation
//! let maxmind_impl = MaxMindGeoIp::new("GeoLite2-City.mmdb")?;
//! let (geo_dataset, _receiver) = NetworkTypedDataset::new(Arc::new(maxmind_impl));
//!
//! // Look up geographic information by IP
//! if let Some(geo_info) = geo_dataset.lookup_by_ip(&ip_addr) {
//!     println!("IP {} is in {}, {}",
//!              ip_addr,
//!              geo_info.city.as_ref().unwrap(),
//!              geo_info.country.as_ref().unwrap());
//! }
//! ```
//!
//! ## Registry and Management
//!
//! ```rust,no_compile,no_run
//! // Register datasets for runtime access
//! let mut registry = EnrichmentRegistry::new();
//! registry.register("geoip", Box::new(geo_dataset.clone()))?;
//! registry.register("users", Box::new(user_dataset.clone()))?;
//!
//! // Access datasets by name at runtime
//! let datasets = registry.get_datasets();
//! for (name, dataset) in datasets {
//!     println!("Available dataset: {}", name);
//! }
//! ```

// Module declarations
pub mod cidr;
pub mod core;
pub mod dataset;
pub mod domain;
pub mod keys;
pub mod manager;
pub mod providers;
pub mod registry;
pub mod types;

// Re-exports for convenience
pub use cidr::CidrDataset;
pub use core::{AnyDataset, DatasetKey, EnrichmentError};
pub use dataset::{
    DatasetUpdate,
    IpNetwork,
    MapDataset,
    // Network dataset framework
    NetworkDataset,
    NetworkDatasetStats,
    NetworkError,
    NetworkTypedDataset,
    NetworkUpdate,
};
pub use domain::{DomainSet, normalize_domain};
pub use keys::{AssetKey, GeoIpKey, ThreatIpKey, UserKey};
pub use manager::{
    DatasetBuilder, DatasetStatistics, EnrichmentManager, ManagedDataset, ManagerConfig,
};
pub use providers::{
    // GeoIP framework
    GeoIpDataset,
    // Threat intelligence framework
    ThreatIntelDataset,
};
pub use registry::EnrichmentRegistry;
pub use types::{AssetInfo, GeoIp, ThreatInfo, UserProfile};
