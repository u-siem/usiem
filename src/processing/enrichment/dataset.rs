//! Strongly-typed dataset implementations for enrichment data storage
//!
//! This module provides the core dataset implementations for the enrichment system:
//!
//! - [`MapDataset<K,V>`] - Hash-map based datasets for key-value lookups
//! - [`NetworkDataset<V>`] - Trait for IP network-based datasets  
//! - [`NetworkTypedDataset<V,U>`] - Wrapper for network datasets in the system
//! - [`DatasetUpdate<K,V>`] - Update operations for modifying dataset contents
//!
//! # Design Philosophy
//!
//! All dataset implementations follow these principles:
//!
//! * **Immutability** - Updates create new dataset instances rather than modifying existing ones
//! * **Type Safety** - Generic parameters ensure compile-time correctness
//! * **Concurrency** - Thread-safe by design using Arc and immutable data structures  
//! * **Performance** - Optimized for read-heavy workloads common in enrichment scenarios
//! * **Channel-based Updates** - Asynchronous update delivery for responsive systems
//!
//! # Update Model
//!
//! The system uses a functional update model where operations return new dataset
//! instances. This enables:
//! - Concurrent access without locks
//! - Audit trails and rollback capabilities
//! - Copy-on-write optimizations
//! - Predictable memory usage patterns
//!
//! # Network vs Key-Value Datasets
//!
//! * **Key-Value** (`MapDataset`) - Direct hash-map lookups, O(1) access time
//! * **Network** (`NetworkDataset`) - IP range lookups, variable access time based on implementation

use crate::processing::enrichment::core::AnyDataset;
use std::any::Any;
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};

/// Generic strongly-typed dataset implementation for key-value enrichment data
///
/// This is the primary dataset implementation for enrichment data that can be
/// looked up using direct key matching. It provides fast O(1) lookups using
/// an internal HashMap and supports concurrent access through Arc-based sharing.
///
/// # Type Parameters
///
/// * `K` - The key type used for lookups (e.g., `Ip`, `Text`, custom types)
/// * `V` - The value type stored (e.g., `GeoIp`, `ThreatInfo`, custom types)
///
/// # Concurrency Model
///
/// The dataset uses an Arc-wrapped HashMap for the data, allowing multiple
/// readers to access the data concurrently without locks. Updates are handled
/// through channels, ensuring thread-safe modification without blocking readers.
///
/// # Update Channel
///
/// Each dataset instance includes a Sender for receiving updates. The manager
/// can send `DatasetUpdate<K,V>` messages through this channel to trigger
/// dataset updates. Updates are processed asynchronously and create new
/// dataset instances.
///
/// # Memory Management
///
/// The Arc-based design means that multiple dataset instances can share the
/// same underlying data, with automatic memory cleanup when all references
/// are dropped. Updates create new HashMap instances rather than modifying
/// existing ones.
///
/// # Usage Example
///
/// ```rust,no_compile,no_run
/// // Create a new GeoIP dataset
/// let (geo_dataset, receiver) = MapDataset::<Ip, GeoIp>::new();
///
/// // Look up geographic information
/// if let Some(geo_info) = geo_dataset.get(&ip_address) {
///     println!("IP {} is in {}", ip_address, geo_info.country.as_ref().unwrap());
/// }
///
/// // Send an update
/// let update = DatasetUpdate::Set {
///     key: ip_address,
///     value: geo_info,
/// };
/// geo_dataset.send_update(update).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct MapDataset<K, V>
where
    K: Clone + Send + Sync + Eq + Hash + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// The underlying data storage, wrapped in Arc for concurrent access
    data: Arc<HashMap<K, V>>,

    /// Channel sender for receiving dataset updates
    sender: Sender<DatasetUpdate<K, V>>,
}

/// Update operations for typed datasets
///
/// This enum defines all possible update operations that can be applied to
/// a `MapDataset<K,V>`. All operations follow the immutability principle
/// and result in new dataset instances rather than in-place modifications.
///
/// # Operation Types
///
/// * **Individual Updates** - `Set` and `Remove` for single key operations
/// * **Bulk Operations** - `Replace` and `Clear` for dataset-wide changes
///
/// # Update Semantics
///
/// * `Set` operations overwrite existing values for the same key
/// * `Remove` operations are idempotent (removing non-existent keys succeeds)
/// * `Replace` completely replaces the dataset contents atomically
/// * `Clear` removes all data, resulting in an empty dataset
///
/// # Performance Considerations
///
/// * Individual operations (`Set`, `Remove`) are O(n) due to HashMap cloning
/// * Bulk operations (`Replace`, `Clear`) avoid intermediate clones
/// * Use batch update methods when applying multiple operations
///
/// # Usage Examples
///
/// ```rust,no_compile,no_run
/// // Add or update a single entry
/// let update = DatasetUpdate::Set {
///     key: ip_addr,
///     value: geo_info,
/// };
///
/// // Remove an entry
/// let update = DatasetUpdate::Remove {
///     key: ip_addr,
/// };
///
/// // Replace entire dataset (bulk load)
/// let update = DatasetUpdate::Replace {
///     data: new_geoip_data,
/// };
///
/// // Clear all data
/// let update = DatasetUpdate::Clear;
/// ```
#[derive(Debug, Clone)]
pub enum DatasetUpdate<K, V> {
    /// Insert or update a key-value pair
    ///
    /// If the key already exists, its value is replaced. If the key doesn't
    /// exist, it's added to the dataset. This operation is idempotent.
    Set { key: K, value: V },

    /// Remove a key from the dataset
    ///
    /// If the key exists, it's removed from the dataset. If the key doesn't
    /// exist, the operation succeeds but has no effect. This operation is
    /// idempotent.
    Remove { key: K },

    /// Replace the entire dataset contents
    ///
    /// This operation atomically replaces all dataset contents with the
    /// provided HashMap. This is more efficient than multiple individual
    /// operations for bulk loading scenarios.
    Replace { data: HashMap<K, V> },

    /// Clear all data from the dataset
    ///
    /// This operation removes all key-value pairs, resulting in an empty
    /// dataset. This is equivalent to `Replace` with an empty HashMap but
    /// more explicit and potentially more efficient.
    Clear,
}

impl<K, V> MapDataset<K, V>
where
    K: Clone + Send + Sync + Eq + Hash + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new typed dataset with an update channel
    pub fn new() -> (Self, Receiver<DatasetUpdate<K, V>>) {
        let (sender, receiver) = mpsc::channel();
        let dataset = Self {
            data: Arc::new(HashMap::new()),
            sender,
        };
        (dataset, receiver)
    }

    /// Create a typed dataset with existing data  
    pub fn with_data(data: HashMap<K, V>) -> Self {
        let (sender, _receiver) = mpsc::channel();
        Self {
            data: Arc::new(data),
            sender,
        }
    }

    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }

    /// Check if a key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.data.contains_key(key)
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the dataset is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get all entries as an iterator
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.data.iter()
    }

    /// Clone the underlying data
    pub fn clone_data(&self) -> HashMap<K, V> {
        (*self.data).clone()
    }

    /// Send an update to the dataset manager
    pub fn insert(
        &self,
        key: K,
        value: V,
    ) -> Result<(), std::sync::mpsc::SendError<DatasetUpdate<K, V>>> {
        self.sender.send(DatasetUpdate::Set { key, value })
    }

    /// Send a remove update to the dataset manager
    pub fn remove(&self, key: K) -> Result<(), std::sync::mpsc::SendError<DatasetUpdate<K, V>>> {
        self.sender.send(DatasetUpdate::Remove { key })
    }

    /// Replace entire dataset content
    pub fn replace(
        &self,
        data: HashMap<K, V>,
    ) -> Result<(), std::sync::mpsc::SendError<DatasetUpdate<K, V>>> {
        self.sender.send(DatasetUpdate::Replace { data })
    }

    /// Clear all dataset content
    pub fn clear(&self) -> Result<(), std::sync::mpsc::SendError<DatasetUpdate<K, V>>> {
        self.sender.send(DatasetUpdate::Clear)
    }

    /// Apply an update to create a new dataset instance
    pub fn apply_update_typed(&self, update: DatasetUpdate<K, V>) -> Self {
        let mut new_data = (*self.data).clone();

        match update {
            DatasetUpdate::Set { key, value } => {
                new_data.insert(key, value);
            }
            DatasetUpdate::Remove { key } => {
                new_data.remove(&key);
            }
            DatasetUpdate::Replace { data } => {
                new_data = data;
            }
            DatasetUpdate::Clear => {
                new_data.clear();
            }
        }

        Self {
            data: Arc::new(new_data),
            sender: self.sender.clone(),
        }
    }

    /// Apply multiple updates at once to create a new dataset instance efficiently
    pub fn apply_batch_updates_typed(&self, updates: Vec<DatasetUpdate<K, V>>) -> Self {
        let mut new_data = (*self.data).clone();

        for update in updates {
            match update {
                DatasetUpdate::Set { key, value } => {
                    new_data.insert(key, value);
                }
                DatasetUpdate::Remove { key } => {
                    new_data.remove(&key);
                }
                DatasetUpdate::Replace { data } => {
                    new_data = data;
                }
                DatasetUpdate::Clear => {
                    new_data.clear();
                }
            }
        }

        Self {
            data: Arc::new(new_data),
            sender: self.sender.clone(),
        }
    }
}

impl<K, V> AnyDataset for MapDataset<K, V>
where
    K: Clone + Send + Sync + Eq + Hash + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn apply_update(&self, update: Box<dyn Any + Send>) -> Box<dyn AnyDataset> {
        if let Ok(typed_update) = update.downcast::<DatasetUpdate<K, V>>() {
            Box::new(self.apply_update_typed(*typed_update))
        } else {
            Box::new(self.clone())
        }
    }

    fn apply_batch_updates(&self, updates: Vec<Box<dyn Any + Send>>) -> Box<dyn AnyDataset> {
        // Convert type-erased updates to typed updates
        let mut typed_updates = Vec::new();

        for update in updates {
            if let Ok(typed_update) = update.downcast::<DatasetUpdate<K, V>>() {
                typed_updates.push(*typed_update);
            }
            // Ignore updates that don't match our type - they're for different datasets
        }

        Box::new(self.apply_batch_updates_typed(typed_updates))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn AnyDataset> {
        Box::new(self.clone())
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// Trait for datasets that support IP network-based lookups
///
/// This trait defines the interface for datasets that can perform lookups
/// based on IP addresses falling within network ranges (CIDR blocks). It's
/// designed to be implemented by external libraries that provide network-based
/// enrichment data like GeoIP databases, threat intelligence feeds, and
/// network classification services.
///
/// # Network Lookup Semantics
///
/// Unlike key-value datasets that require exact key matches, network datasets
/// perform range-based lookups. When given an IP address, implementations
/// should find the most specific network range that contains that IP and
/// return the associated value.
///
/// # Implementation Requirements
///
/// Implementations must be:
/// * **Thread-safe** - Concurrent lookups must be safe
/// * **Efficient** - Lookups should be optimized (e.g., using radix trees)
/// * **Consistent** - Same IP should always return same result for same data
/// * **Immutable** - Updates should create new instances, not modify existing ones
///
/// # Common Use Cases
///
/// * **GeoIP Databases** - IP to geographic location mapping
/// * **Threat Intelligence** - IP reputation and threat classification
/// * **Network Classification** - ISP, hosting provider, proxy detection
/// * **Access Control** - IP-based allow/deny lists with CIDR ranges
///
/// # Performance Considerations
///
/// Network lookups are typically more expensive than hash-map lookups due to
/// the need to find the best matching network. Implementations should use
/// efficient data structures like:
/// - Radix trees (tries) for fast prefix matching
/// - Interval trees for range-based lookups
/// - Compressed representations for memory efficiency
///
/// # Example Implementation Pattern
///
/// ```rust,no_compile,no_run
/// struct MyGeoIpDataset {
///     // Efficient data structure for network lookups
///     networks: RadixTree<IpNetwork, GeoIp>,
/// }
///
/// impl NetworkDataset<GeoIp> for MyGeoIpDataset {
///     fn lookup_by_ip(&self, ip: &IpAddr) -> Option<Cow<'_, GeoIp>> {
///         self.networks.longest_prefix_match(ip).map(Cow::Borrowed)
///     }
///     
///     fn network_count(&self) -> usize {
///         self.networks.len()
///     }
///     
///     fn is_empty(&self) -> bool {
///         self.networks.is_empty()
///     }
/// }
/// ```
pub trait NetworkDataset<V>: Send + Sync
where
    V: Clone + Send + Sync + 'static,
{
    /// Look up a value by IP address (finds the most specific matching network)
    ///
    /// Given an IP address, this method should find the network range that
    /// contains the IP and return the associated value. If multiple networks
    /// contain the IP, the most specific (longest prefix) should be returned.
    ///
    /// # Parameters
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// * `Some(value)` - If a network containing the IP is found
    /// * `None` - If no network contains the IP
    ///
    /// In-memory tables return [`Cow::Borrowed`]; readers that decode a
    /// record per lookup (memory-mapped GeoIP databases, say) return
    /// [`Cow::Owned`].
    ///
    /// # Implementation Notes
    ///
    /// - Must handle both IPv4 and IPv6 addresses appropriately
    /// - Should return the most specific match when multiple ranges overlap
    /// - Must be thread-safe for concurrent access
    fn lookup_by_ip(&self, ip: &IpAddr) -> Option<Cow<'_, V>>;

    /// Check if the dataset contains any networks
    ///
    /// This is a convenience method for determining if the dataset is empty.
    /// It should be more efficient than checking if `network_count() == 0`.
    ///
    /// # Returns
    ///
    /// * `true` - If the dataset contains no network ranges
    /// * `false` - If the dataset contains at least one network range
    fn is_empty(&self) -> bool;

    /// Get the number of network entries in the dataset
    ///
    /// Returns the total count of network ranges stored in the dataset.
    /// This is useful for monitoring, capacity planning, and debugging.
    ///
    /// # Returns
    ///
    /// The number of network ranges in the dataset.
    fn network_count(&self) -> usize;

    /// Get dataset statistics for monitoring and debugging
    ///
    /// Returns a `NetworkDatasetStats` structure containing useful metrics
    /// about the dataset. This default implementation provides basic statistics,
    /// but implementations can override this to provide more detailed metrics.
    ///
    /// # Returns
    ///
    /// A `NetworkDatasetStats` structure with dataset metrics.
    fn get_stats(&self) -> NetworkDatasetStats {
        NetworkDatasetStats {
            network_count: self.network_count(),
            is_empty: self.is_empty(),
        }
    }
}

/// Statistics and metrics for network-based datasets
///
/// This structure provides essential metrics about network datasets that are
/// useful for monitoring, debugging, and capacity planning. It's returned by
/// the `get_stats()` method of `NetworkDataset` implementations.
///
/// # Fields
///
/// * `network_count` - Total number of network ranges in the dataset
/// * `is_empty` - Whether the dataset contains any data
///
/// # Usage
///
/// ```rust,no_compile,no_run
/// let stats = dataset.get_stats();
/// log::info!("Dataset has {} networks, empty: {}",
///            stats.network_count, stats.is_empty);
///
/// // Capacity planning
/// if stats.network_count > 1_000_000 {
///     log::warn!("Large dataset detected, consider optimization");
/// }
/// ```
///
/// # Extension
///
/// External implementations can extend this structure by implementing custom
/// `get_stats()` methods that return additional metrics specific to their
/// data structures and use cases.
#[derive(Debug, Clone)]
pub struct NetworkDatasetStats {
    /// Total number of network ranges stored in the dataset
    pub network_count: usize,

    /// Whether the dataset is empty (contains no network ranges)
    pub is_empty: bool,
}

/// Update operations for network-based datasets
///
/// This trait defines the interface for updates that can be applied to network
/// datasets. Unlike simple key-value updates, network updates may involve
/// complex operations like adding/removing CIDR blocks, merging ranges, or
/// bulk loading from external sources.
///
/// # Design Philosophy
///
/// Network updates follow the same immutability principles as other dataset
/// updates - they create new dataset instances rather than modifying existing
/// ones. This ensures thread safety and enables features like rollback and
/// audit trails.
///
/// # Implementation Responsibility
///
/// External libraries that implement `NetworkDataset` are responsible for
/// defining their own update types that implement this trait. This allows
/// each implementation to optimize for its specific data structure and
/// use case requirements.
///
/// # Common Update Patterns
///
/// * **Single Network Updates** - Add/remove individual CIDR blocks
/// * **Bulk Updates** - Load complete datasets from files or APIs
/// * **Incremental Updates** - Apply deltas from threat feeds or GeoIP updates
/// * **Merge Operations** - Combine data from multiple sources
///
/// # Example Implementation
///
/// ```rust,no_compile,no_run
/// #[derive(Debug, Clone)]
/// enum GeoIpUpdate {
///     AddNetwork { cidr: IpNetwork, geo_info: GeoIp },
///     RemoveNetwork { cidr: IpNetwork },
///     BulkLoad { networks: Vec<(IpNetwork, GeoIp)> },
///     Clear,
/// }
///
/// impl NetworkUpdate for GeoIpUpdate {
///     type Value = GeoIp;
///     
///     fn apply_to_dataset(&self, dataset: &dyn NetworkDataset<GeoIp>)
///         -> Box<dyn NetworkDataset<GeoIp>>
///     {
///         match self {
///             GeoIpUpdate::AddNetwork { cidr, geo_info } => {
///                 // Create new dataset with added network
///             },
///             GeoIpUpdate::BulkLoad { networks } => {
///                 // Replace entire dataset
///             },
///             // ... handle other variants
///         }
///     }
/// }
/// ```
///
/// # Thread Safety
///
/// Implementations must be thread-safe since updates may be applied
/// concurrently. The immutable update model helps ensure this safety.
pub trait NetworkUpdate: Send + Sync + Clone + std::fmt::Debug {
    /// The value type stored in the target network dataset
    ///
    /// This must match the value type of the `NetworkDataset` that this
    /// update will be applied to. It ensures type safety at compile time.
    type Value: Clone + Send + Sync + 'static;

    /// Apply this update to create a new dataset instance
    ///
    /// This method takes an existing network dataset and applies the update
    /// operation, returning a new dataset instance with the changes applied.
    /// The original dataset remains unchanged.
    ///
    /// # Parameters
    ///
    /// * `dataset` - The current network dataset to update
    ///
    /// # Returns
    ///
    /// A new `NetworkDataset` instance with the update applied. The returned
    /// dataset should have the same type as the input dataset but with
    /// modified contents.
    ///
    /// # Implementation Notes
    ///
    /// - Must not modify the input dataset
    /// - Should handle errors gracefully (e.g., invalid CIDR blocks)
    /// - May optimize by sharing unchanged data between old and new instances
    /// - Should maintain consistency (e.g., overlapping ranges handled properly)
    fn apply_to_dataset(
        &self,
        dataset: &dyn NetworkDataset<Self::Value>,
    ) -> Box<dyn NetworkDataset<Self::Value>>;
}

/// Generic wrapper for network datasets to integrate with the enrichment system
#[derive(Clone)]
pub struct NetworkTypedDataset<V, U>
where
    V: Clone + Send + Sync + 'static,
    U: NetworkUpdate<Value = V> + 'static,
{
    /// The underlying network dataset implementation
    dataset: Arc<dyn NetworkDataset<V>>,
    /// Channel for receiving updates
    sender: Sender<U>,
}

impl<V, U> NetworkTypedDataset<V, U>
where
    V: Clone + Send + Sync + 'static,
    U: NetworkUpdate<Value = V> + 'static,
{
    /// Create a new network dataset with an update channel
    pub fn new(initial_dataset: Arc<dyn NetworkDataset<V>>) -> (Self, Receiver<U>) {
        let (sender, receiver) = mpsc::channel();
        let dataset = Self {
            dataset: initial_dataset,
            sender,
        };
        (dataset, receiver)
    }

    /// Look up a value by IP address
    pub fn lookup_by_ip(&self, ip: &IpAddr) -> Option<Cow<'_, V>> {
        self.dataset.lookup_by_ip(ip)
    }

    /// Send an update to the dataset manager
    pub fn send_update(&self, update: U) -> Result<(), std::sync::mpsc::SendError<U>> {
        self.sender.send(update)
    }

    /// Get network dataset statistics
    pub fn get_stats(&self) -> NetworkDatasetStats {
        self.dataset.get_stats()
    }

    /// Apply an update to create a new dataset instance
    pub fn apply_network_update(&self, update: U) -> Self {
        let new_dataset = update.apply_to_dataset(self.dataset.as_ref());
        Self {
            dataset: Arc::from(new_dataset),
            sender: self.sender.clone(),
        }
    }

    /// Apply multiple updates at once
    pub fn apply_batch_network_updates(&self, updates: Vec<U>) -> Self {
        let mut current_dataset = self.dataset.clone();

        for update in updates {
            let new_dataset = update.apply_to_dataset(current_dataset.as_ref());
            current_dataset = Arc::from(new_dataset);
        }

        Self {
            dataset: current_dataset,
            sender: self.sender.clone(),
        }
    }
}

/// AnyDataset implementation for network datasets
impl<V, U> AnyDataset for NetworkTypedDataset<V, U>
where
    V: Clone + Send + Sync + 'static,
    U: NetworkUpdate<Value = V> + 'static,
{
    fn apply_update(&self, update: Box<dyn Any + Send>) -> Box<dyn AnyDataset> {
        if let Ok(network_update) = update.downcast::<U>() {
            Box::new(self.apply_network_update(*network_update))
        } else {
            Box::new(self.clone())
        }
    }

    fn apply_batch_updates(&self, updates: Vec<Box<dyn Any + Send>>) -> Box<dyn AnyDataset> {
        let mut typed_updates = Vec::new();

        for update in updates {
            if let Ok(network_update) = update.downcast::<U>() {
                typed_updates.push(*network_update);
            }
        }

        Box::new(self.apply_batch_network_updates(typed_updates))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn AnyDataset> {
        Box::new(self.clone())
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// Represents an IP network range for dataset keys
/// External libraries can implement their own CIDR types using this as a guide
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpNetwork {
    /// IPv4 network with prefix length
    V4 {
        addr: std::net::Ipv4Addr,
        prefix_len: u8,
    },
    /// IPv6 network with prefix length
    V6 {
        addr: std::net::Ipv6Addr,
        prefix_len: u8,
    },
}

/// A single address: `/32` for IPv4, `/128` for IPv6.
impl From<IpAddr> for IpNetwork {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(addr) => IpNetwork::V4 {
                addr,
                prefix_len: 32,
            },
            IpAddr::V6(addr) => IpNetwork::V6 {
                addr,
                prefix_len: 128,
            },
        }
    }
}

impl IpNetwork {
    /// Create a new IPv4 network
    pub fn new_v4(addr: std::net::Ipv4Addr, prefix_len: u8) -> Result<Self, NetworkError> {
        if prefix_len > 32 {
            return Err(NetworkError::InvalidPrefix);
        }
        Ok(IpNetwork::V4 { addr, prefix_len })
    }

    /// Create a new IPv6 network
    pub fn new_v6(addr: std::net::Ipv6Addr, prefix_len: u8) -> Result<Self, NetworkError> {
        if prefix_len > 128 {
            return Err(NetworkError::InvalidPrefix);
        }
        Ok(IpNetwork::V6 { addr, prefix_len })
    }

    /// Check if an IP address belongs to this network
    /// External libraries should provide optimized implementations
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpNetwork::V4 { addr, prefix_len }, IpAddr::V4(test_ip)) => {
                let mask = if *prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let network = u32::from(*addr) & mask;
                let test = u32::from(*test_ip) & mask;
                network == test
            }
            (IpNetwork::V6 { addr, prefix_len }, IpAddr::V6(test_ip)) => {
                let bytes = addr.octets();
                let test_bytes = test_ip.octets();
                let full_bytes = *prefix_len / 8;
                let remainder = *prefix_len % 8;

                // Check full bytes
                if bytes[..full_bytes as usize] != test_bytes[..full_bytes as usize] {
                    return false;
                }

                // Check partial byte if any
                if remainder > 0 && full_bytes < 16 {
                    let mask = 0xFF << (8 - remainder);
                    let network_byte = bytes[full_bytes as usize] & mask;
                    let test_byte = test_bytes[full_bytes as usize] & mask;
                    return network_byte == test_byte;
                }

                true
            }
            _ => false, // IPv4 address against IPv6 network or vice versa
        }
    }

    /// Get the network address as an IpAddr
    pub fn network_addr(&self) -> IpAddr {
        match self {
            IpNetwork::V4 { addr, .. } => IpAddr::V4(*addr),
            IpNetwork::V6 { addr, .. } => IpAddr::V6(*addr),
        }
    }

    /// Get the prefix length
    pub fn prefix_len(&self) -> u8 {
        match self {
            IpNetwork::V4 { prefix_len, .. } | IpNetwork::V6 { prefix_len, .. } => *prefix_len,
        }
    }
}

impl std::str::FromStr for IpNetwork {
    type Err = NetworkError;

    /// Parses `addr/prefix` or a bare address (a host network: `/32` or
    /// `/128`). Host bits below the prefix are cleared, so `10.1.2.3/8`
    /// becomes `10.0.0.0/8`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| NetworkError::ParseError(format!("invalid address in {text:?}")))?;
        let prefix = match prefix {
            Some(p) => Some(
                p.parse::<u8>()
                    .map_err(|_| NetworkError::ParseError(format!("invalid prefix in {text:?}")))?,
            ),
            None => None,
        };
        match addr {
            IpAddr::V4(addr) => {
                let prefix_len = prefix.unwrap_or(32);
                IpNetwork::new_v4(addr, prefix_len)?;
                let bits = u32::from(addr) & v4_mask(prefix_len);
                IpNetwork::new_v4(bits.into(), prefix_len)
            }
            IpAddr::V6(addr) => {
                let prefix_len = prefix.unwrap_or(128);
                IpNetwork::new_v6(addr, prefix_len)?;
                let bits = u128::from(addr) & v6_mask(prefix_len);
                IpNetwork::new_v6(bits.into(), prefix_len)
            }
        }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network_addr(), self.prefix_len())
    }
}

/// Network mask for an IPv4 prefix length (at most 32).
pub(crate) fn v4_mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        p => !0u32 << (32 - u32::from(p.min(32))),
    }
}

/// Network mask for an IPv6 prefix length (at most 128).
pub(crate) fn v6_mask(prefix_len: u8) -> u128 {
    match prefix_len {
        0 => 0,
        p => !0u128 << (128 - u32::from(p.min(128))),
    }
}

/// Errors for network operations
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkError {
    /// Invalid prefix length
    InvalidPrefix,
    /// Network parsing error
    ParseError(String),
    /// Lookup error
    LookupError(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::InvalidPrefix => write!(f, "Invalid network prefix length"),
            NetworkError::ParseError(msg) => write!(f, "Network parse error: {}", msg),
            NetworkError::LookupError(msg) => write!(f, "Network lookup error: {}", msg),
        }
    }
}

impl std::error::Error for NetworkError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::Text;

    #[test]
    fn test_typed_dataset_new() {
        let (dataset, receiver) = MapDataset::<Text, String>::new();

        // Test that the dataset starts empty
        assert!(dataset.is_empty());
        assert_eq!(dataset.len(), 0);

        // Drop receiver to avoid warnings
        drop(receiver);
    }

    #[test]
    fn test_typed_dataset_with_data() {
        let mut initial_data = HashMap::new();
        initial_data.insert(Text::from("key1"), "value1".to_string());
        initial_data.insert(Text::from("key2"), "value2".to_string());

        let dataset = MapDataset::with_data(initial_data.clone());

        assert!(!dataset.is_empty());
        assert_eq!(dataset.len(), 2);

        assert_eq!(
            dataset.get(&Text::from("key1")),
            Some(&"value1".to_string())
        );
        assert_eq!(
            dataset.get(&Text::from("key2")),
            Some(&"value2".to_string())
        );
        assert_eq!(dataset.get(&Text::from("key3")), None);
    }

    #[test]
    fn test_dataset_update_variants() {
        // Test Set update
        let set_update = DatasetUpdate::Set {
            key: Text::from("test_key"),
            value: "test_value".to_string(),
        };

        match set_update {
            DatasetUpdate::Set { key, value } => {
                assert_eq!(key.to_string(), "test_key");
                assert_eq!(value, "test_value");
            }
            _ => panic!("Should be Set variant"),
        }

        // Test Remove update
        let remove_update = DatasetUpdate::Remove::<Text, String> {
            key: Text::from("test_key"),
        };

        match remove_update {
            DatasetUpdate::Remove { key } => {
                assert_eq!(key.to_string(), "test_key");
            }
            _ => panic!("Should be Remove variant"),
        }

        // Test Replace update
        let mut new_data = HashMap::new();
        new_data.insert(Text::from("new_key"), "new_value".to_string());

        let replace_update = DatasetUpdate::Replace { data: new_data };

        match replace_update {
            DatasetUpdate::Replace { data } => {
                assert_eq!(data.len(), 1);
                assert!(data.contains_key(&Text::from("new_key")));
            }
            _ => panic!("Should be Replace variant"),
        }

        // Test Clear update
        let clear_update = DatasetUpdate::Clear::<Text, String>;

        match clear_update {
            DatasetUpdate::Clear => (), // Expected
            _ => panic!("Should be Clear variant"),
        }
    }

    #[test]
    fn test_dataset_apply_updates() {
        let (dataset, _receiver) = MapDataset::<Text, String>::new();

        // Test Set update
        let set_update = DatasetUpdate::Set {
            key: Text::from("key1"),
            value: "value1".to_string(),
        };

        let updated_dataset = dataset.apply_update_typed(set_update);
        assert_eq!(updated_dataset.len(), 1);
        assert_eq!(
            updated_dataset.get(&Text::from("key1")),
            Some(&"value1".to_string())
        );

        // Test that original dataset is unchanged
        assert_eq!(dataset.len(), 0);

        // Test Remove update
        let remove_update = DatasetUpdate::Remove {
            key: Text::from("key1"),
        };

        let removed_dataset = updated_dataset.apply_update_typed(remove_update);
        assert_eq!(removed_dataset.len(), 0);
        assert_eq!(removed_dataset.get(&Text::from("key1")), None);
    }

    #[test]
    fn test_dataset_batch_updates() {
        let (dataset, _receiver) = MapDataset::<Text, String>::new();

        let updates = vec![
            DatasetUpdate::Set {
                key: Text::from("key1"),
                value: "value1".to_string(),
            },
            DatasetUpdate::Set {
                key: Text::from("key2"),
                value: "value2".to_string(),
            },
            DatasetUpdate::Set {
                key: Text::from("key3"),
                value: "value3".to_string(),
            },
        ];

        let updated_dataset = dataset.apply_batch_updates_typed(updates);

        assert_eq!(updated_dataset.len(), 3);
        assert_eq!(
            updated_dataset.get(&Text::from("key1")),
            Some(&"value1".to_string())
        );
        assert_eq!(
            updated_dataset.get(&Text::from("key2")),
            Some(&"value2".to_string())
        );
        assert_eq!(
            updated_dataset.get(&Text::from("key3")),
            Some(&"value3".to_string())
        );

        // Test original is unchanged
        assert_eq!(dataset.len(), 0);
    }

    #[test]
    fn test_dataset_clear_update() {
        let mut initial_data = HashMap::new();
        initial_data.insert(Text::from("key1"), "value1".to_string());
        initial_data.insert(Text::from("key2"), "value2".to_string());

        let dataset = MapDataset::with_data(initial_data);
        assert_eq!(dataset.len(), 2);

        let clear_update = DatasetUpdate::Clear;
        let cleared_dataset = dataset.apply_update_typed(clear_update);

        assert_eq!(cleared_dataset.len(), 0);
        assert!(cleared_dataset.is_empty());
    }

    #[test]
    fn test_dataset_replace_update() {
        let mut initial_data = HashMap::new();
        initial_data.insert(Text::from("old_key"), "old_value".to_string());

        let dataset = MapDataset::with_data(initial_data);
        assert_eq!(dataset.len(), 1);

        let mut new_data = HashMap::new();
        new_data.insert(Text::from("new_key1"), "new_value1".to_string());
        new_data.insert(Text::from("new_key2"), "new_value2".to_string());

        let replace_update = DatasetUpdate::Replace { data: new_data };
        let replaced_dataset = dataset.apply_update_typed(replace_update);

        assert_eq!(replaced_dataset.len(), 2);
        assert_eq!(replaced_dataset.get(&Text::from("old_key")), None);
        assert_eq!(
            replaced_dataset.get(&Text::from("new_key1")),
            Some(&"new_value1".to_string())
        );
        assert_eq!(
            replaced_dataset.get(&Text::from("new_key2")),
            Some(&"new_value2".to_string())
        );
    }

    #[test]
    fn test_any_dataset_implementation() {
        let (dataset, _receiver) = MapDataset::<Text, String>::new();

        // Test type_name
        assert_eq!(
            dataset.type_name(),
            std::any::type_name::<MapDataset<Text, String>>()
        );

        // Test as_any and downcasting
        let any_dataset: &dyn AnyDataset = &dataset;
        let recovered = any_dataset
            .as_any()
            .downcast_ref::<MapDataset<Text, String>>();
        assert!(recovered.is_some());

        // Test clone_box
        let cloned = dataset.clone_box();
        assert_eq!(cloned.type_name(), dataset.type_name());
    }

    #[test]
    fn test_ip_network_creation() {
        // Test IPv4 network creation
        let ipv4_addr = std::net::Ipv4Addr::new(192, 168, 1, 0);
        let ipv4_network = IpNetwork::new_v4(ipv4_addr, 24);
        assert!(ipv4_network.is_ok());

        let network = ipv4_network.unwrap();
        assert_eq!(network.prefix_len(), 24);

        // Test invalid prefix
        let invalid_network = IpNetwork::new_v4(ipv4_addr, 33);
        assert!(invalid_network.is_err());
        assert_eq!(invalid_network.unwrap_err(), NetworkError::InvalidPrefix);

        // Test IPv6 network creation
        let ipv6_addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let ipv6_network = IpNetwork::new_v6(ipv6_addr, 64);
        assert!(ipv6_network.is_ok());

        let network = ipv6_network.unwrap();
        assert_eq!(network.prefix_len(), 64);

        // Test invalid IPv6 prefix
        let invalid_ipv6_network = IpNetwork::new_v6(ipv6_addr, 129);
        assert!(invalid_ipv6_network.is_err());
    }

    #[test]
    fn test_ip_network_contains() {
        // Test IPv4 network containment
        let network = IpNetwork::new_v4(std::net::Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();

        let contained_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
        let not_contained_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 2, 100));

        assert!(network.contains(&contained_ip));
        assert!(!network.contains(&not_contained_ip));

        // Test IPv6 network containment
        let ipv6_network =
            IpNetwork::new_v6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 64)
                .unwrap();

        let contained_ipv6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let not_contained_ipv6 =
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1));

        assert!(ipv6_network.contains(&contained_ipv6));
        assert!(!ipv6_network.contains(&not_contained_ipv6));

        // Test IPv4 vs IPv6 mismatch
        assert!(!network.contains(&contained_ipv6));
        assert!(!ipv6_network.contains(&contained_ip));
    }

    #[test]
    fn test_network_dataset_stats() {
        let stats = NetworkDatasetStats {
            network_count: 42,
            is_empty: false,
        };

        assert_eq!(stats.network_count, 42);
        assert!(!stats.is_empty);

        let empty_stats = NetworkDatasetStats {
            network_count: 0,
            is_empty: true,
        };

        assert_eq!(empty_stats.network_count, 0);
        assert!(empty_stats.is_empty);
    }

    #[test]
    fn test_network_error_display() {
        let invalid_prefix_error = NetworkError::InvalidPrefix;
        assert_eq!(
            invalid_prefix_error.to_string(),
            "Invalid network prefix length"
        );

        let parse_error = NetworkError::ParseError("invalid CIDR".to_string());
        assert!(parse_error.to_string().contains("Network parse error"));

        let lookup_error = NetworkError::LookupError("timeout".to_string());
        assert!(lookup_error.to_string().contains("Network lookup error"));
    }
}
