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
//! * [`ThreatIntelDataset`] - Interface for threat intelligence providers
//!
//! # Standard Data Types
//!
//! The module re-exports enhanced versions of standard enrichment types:
//! * [`GeoIp`] - Geographic IP information structure
//! * [`ThreatInfo`] - Threat intelligence data structure
//!
//! Severity and confidence use the shared scales in
//! [`crate::processing::rating`]; feeds that score 1-10 convert with
//! [`crate::processing::rating::Severity::from_score`].
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
pub use crate::processing::enrichment::types::{GeoIp, ThreatInfo};

/// Framework interface for IP-to-location mappings
/// External GeoIP libraries implement this trait
pub trait GeoIpDataset: NetworkDataset<GeoIp> {
    /// Look up geographic information by IP
    fn lookup_geo(&self, ip: &IpAddr) -> Option<Cow<'_, GeoIp>> {
        self.lookup_by_ip(ip)
    }
}

/// Framework interface for threat intelligence datasets
/// External threat intel libraries implement this trait
pub trait ThreatIntelDataset: NetworkDataset<ThreatInfo> {
    /// Look up threat information by IP
    fn lookup_threat(&self, ip: &IpAddr) -> Option<Cow<'_, ThreatInfo>> {
        self.lookup_by_ip(ip)
    }

    /// Check if IP is in any threat category
    fn is_threat(&self, ip: &IpAddr) -> bool {
        self.lookup_threat(ip).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::{Text, Timestamp};
    use crate::processing::rating::{Confidence, Severity};

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
    fn test_threat_info_data_structure() {
        let threat = ThreatInfo {
            threat_type: Text::from("malware"),
            severity: Severity::High,
            confidence: Confidence::new(90),
            description: Some(Text::from("Known botnet C&C")),
            source: Text::from("Mock Threat Feed"),
            first_seen: Some(Timestamp::from_secs(1640995200)),
            last_seen: Some(Timestamp::from_secs(1672531200)),
        };

        assert_eq!(threat.threat_type.to_string(), "malware");
        assert_eq!(threat.severity, Severity::High);
        assert_eq!(threat.confidence.as_percent(), 90);
        assert_eq!(
            threat.description.as_ref().unwrap().to_string(),
            "Known botnet C&C"
        );
        assert_eq!(threat.source.to_string(), "Mock Threat Feed");
        assert_eq!(threat.first_seen, Some(Timestamp::from_secs(1640995200)));
        assert_eq!(threat.last_seen, Some(Timestamp::from_secs(1672531200)));
    }

    #[test]
    fn test_threat_info_default() {
        let threat = ThreatInfo::default();

        assert_eq!(threat.threat_type.to_string(), "unknown");
        assert_eq!(threat.severity, Severity::Low);
        assert_eq!(threat.confidence, Confidence::NONE);
        assert!(threat.description.is_none());
        assert_eq!(threat.source.to_string(), "unknown");
        assert!(threat.first_seen.is_none());
        assert!(threat.last_seen.is_none());
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

    #[test]
    fn test_data_types_are_cloneable() {
        let geo = GeoIp::default();
        let _geo_clone = geo.clone();

        let threat = ThreatInfo::default();
        let _threat_clone = threat.clone();
    }

    #[test]
    fn test_threat_confidence_ranges() {
        let low_confidence = ThreatInfo {
            threat_type: Text::from("suspicious"),
            severity: Severity::Low,
            confidence: Confidence::new(25),
            description: None,
            source: Text::from("Automated Analysis"),
            first_seen: None,
            last_seen: None,
        };

        let high_confidence = ThreatInfo {
            threat_type: Text::from("malware"),
            severity: Severity::High,
            confidence: Confidence::new(95),
            description: Some(Text::from("Confirmed by multiple sources")),
            source: Text::from("Threat Intelligence Feed"),
            first_seen: Some(Timestamp::from_secs(1640995200)),
            last_seen: Some(Timestamp::from_secs(1672531200)),
        };

        assert!(low_confidence.confidence < Confidence::new(50));
        assert!(high_confidence.confidence > Confidence::new(90));
        assert!(high_confidence.severity > low_confidence.severity);
    }
}
