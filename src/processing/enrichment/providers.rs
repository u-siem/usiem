//! Concrete provider implementations and interfaces provided by the framework
//!
//! This module contains the built-in provider interfaces and data structures that
//! external libraries can implement and use for common enrichment scenarios. It
//! provides a standard contract between the enrichment framework and external
//! data providers.
//!
//! # Provider Interfaces
//!
//! * [`GeoIpDataset`] - Interface for geographic IP location services
//!
//! # Standard Data Types
//!
//! * [`GeoIp`] - Geographic IP information structure (re-exported)
//!
//! # Design Principles
//!
//! * **Framework Interfaces Only** - No concrete implementations, just contracts
//! * **External Library Responsibility** - Actual data loading and storage handled externally
//! * **Standard Types** - Common structures for interoperability
//! * **Flexible Implementation** - Providers can extend types and interfaces as needed
//!
//! # Usage Pattern
//!
//! External libraries implement the provider traits and integrate with the
//! enrichment system:
//!
//! ```rust,no_compile,no_run
//! // External library implements the interface
//! struct MaxMindGeoIp {
//!     // Internal MaxMind-specific data structures
//! }
//!
//! impl NetworkDataset<GeoIp> for MaxMindGeoIp { /* ... */ }
//! impl GeoIpDataset for MaxMindGeoIp { /* ... */ }
//!
//! // Application code uses the standard interface
//! let geo_dataset = NetworkTypedDataset::new(Arc::new(maxmind_impl));
//! ```

use crate::processing::enrichment::dataset::NetworkDataset;
use std::borrow::Cow;
use std::net::IpAddr;

// Re-export the enhanced types from the types module
pub use crate::processing::enrichment::types::GeoIp;

/// Framework interface for IP-to-location mappings
/// External GeoIP libraries implement this trait
pub trait GeoIpDataset: NetworkDataset<GeoIp> {
    /// Look up geographic information by IP
    fn lookup_geo(&self, ip: &IpAddr) -> Option<Cow<'_, GeoIp>> {
        self.lookup_by_ip(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::Text;

    #[test]
    fn test_geoip_data_structure() {
        let geo = GeoIp {
            country_code: Some(Text::from("US")),
            country: Some(Text::from("United States")),
            city: Some(Text::from("Mountain View")),
            latitude: Some(37.386),
            longitude: Some(-122.084),
            asn: Some(15169),
            organization: Some(Text::from("Google LLC")),
            isp: Some(Text::from("Google")),
        };

        assert_eq!(geo.country_code.as_ref().unwrap().to_string(), "US");
        assert_eq!(geo.country.as_ref().unwrap().to_string(), "United States");
        assert_eq!(geo.city.as_ref().unwrap().to_string(), "Mountain View");
        assert_eq!(geo.latitude.unwrap(), 37.386);
        assert_eq!(geo.longitude.unwrap(), -122.084);
        assert_eq!(geo.asn.unwrap(), 15169);
        assert_eq!(geo.organization.as_ref().unwrap().to_string(), "Google LLC");
        assert_eq!(geo.isp.as_ref().unwrap().to_string(), "Google");
    }

    #[test]
    fn test_geoip_partial_data() {
        let geo = GeoIp {
            country_code: Some(Text::from("DE")),
            country: Some(Text::from("Germany")),
            city: None,     // Missing city data
            latitude: None, // Missing coordinates
            longitude: None,
            asn: Some(3320),
            organization: Some(Text::from("Deutsche Telekom AG")),
            isp: None, // Missing ISP data
        };

        assert_eq!(geo.country_code.as_ref().unwrap().to_string(), "DE");
        assert_eq!(geo.country.as_ref().unwrap().to_string(), "Germany");
        assert!(geo.city.is_none());
        assert!(geo.latitude.is_none());
        assert!(geo.longitude.is_none());
        assert_eq!(geo.asn.unwrap(), 3320);
        assert_eq!(
            geo.organization.as_ref().unwrap().to_string(),
            "Deutsche Telekom AG"
        );
        assert!(geo.isp.is_none());
    }
}
