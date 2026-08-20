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
//! # Helper Modules
//!
//! * [`threat_severity`] - Utilities for working with threat severity scores
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
use std::net::IpAddr;

// Re-export the enhanced types from the types module
pub use crate::processing::enrichment::types::{GeoIp, ThreatInfo};

/// Framework interface for IP-to-location mappings
/// External GeoIP libraries implement this trait
pub trait GeoIpDataset: NetworkDataset<GeoIp> {
    /// Look up geographic information by IP
    fn lookup_geo(&self, ip: &IpAddr) -> Option<&GeoIp> {
        self.lookup_by_ip(ip)
    }
}

/// Framework interface for threat intelligence datasets
/// External threat intel libraries implement this trait
pub trait ThreatIntelDataset: NetworkDataset<ThreatInfo> {
    /// Look up threat information by IP
    fn lookup_threat(&self, ip: &IpAddr) -> Option<&ThreatInfo> {
        self.lookup_by_ip(ip)
    }

    /// Check if IP is in any threat category
    fn is_threat(&self, ip: &IpAddr) -> bool {
        self.lookup_threat(ip).is_some()
    }
}

/// Threat severity levels using the existing 1-10 scale from ThreatInfo
/// but providing named constants for common severity levels
pub mod threat_severity {
    /// Low severity (1-3 on the scale)
    pub const LOW: u8 = 2;
    /// Medium severity (4-6 on the scale)
    pub const MEDIUM: u8 = 5;
    /// High severity (7-9 on the scale)
    pub const HIGH: u8 = 8;
    /// Critical severity (10 on the scale)
    pub const CRITICAL: u8 = 10;

    /// Check if a severity value is low
    pub fn is_low(severity: u8) -> bool {
        (1..=3).contains(&severity)
    }

    /// Check if a severity value is medium
    pub fn is_medium(severity: u8) -> bool {
        (4..=6).contains(&severity)
    }

    /// Check if a severity value is high
    pub fn is_high(severity: u8) -> bool {
        (7..=9).contains(&severity)
    }

    /// Check if a severity value is critical
    pub fn is_critical(severity: u8) -> bool {
        severity == 10
    }
}

#[cfg(test)]
mod tests {
    use super::threat_severity;
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
    fn test_threat_info_data_structure() {
        let threat = ThreatInfo {
            threat_type: Text::from("malware"),
            severity: 8,
            confidence: 90,
            description: Some(Text::from("Known botnet C&C")),
            source: Text::from("Mock Threat Feed"),
            first_seen: Some(1640995200),
            last_seen: Some(1672531200),
        };

        assert_eq!(threat.threat_type.to_string(), "malware");
        assert_eq!(threat.severity, 8);
        assert_eq!(threat.confidence, 90);
        assert_eq!(
            threat.description.as_ref().unwrap().to_string(),
            "Known botnet C&C"
        );
        assert_eq!(threat.source.to_string(), "Mock Threat Feed");
        assert_eq!(threat.first_seen.unwrap(), 1640995200);
        assert_eq!(threat.last_seen.unwrap(), 1672531200);
    }

    #[test]
    fn test_threat_info_default() {
        let threat = ThreatInfo::default();

        assert_eq!(threat.threat_type.to_string(), "unknown");
        assert_eq!(threat.severity, 1);
        assert_eq!(threat.confidence, 0);
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
    fn test_severity_helpers() {
        // Test low severity
        assert!(threat_severity::is_low(1));
        assert!(threat_severity::is_low(3));
        assert!(!threat_severity::is_low(4));
        assert!(!threat_severity::is_low(0)); // Out of range

        // Test medium severity
        assert!(threat_severity::is_medium(4));
        assert!(threat_severity::is_medium(6));
        assert!(!threat_severity::is_medium(3));
        assert!(!threat_severity::is_medium(7));

        // Test high severity
        assert!(threat_severity::is_high(7));
        assert!(threat_severity::is_high(9));
        assert!(!threat_severity::is_high(6));
        assert!(!threat_severity::is_high(10));

        // Test critical severity
        assert!(threat_severity::is_critical(10));
        assert!(!threat_severity::is_critical(9));
        assert!(!threat_severity::is_critical(11)); // Out of range
    }

    #[test]
    fn test_severity_ranges() {
        // Verify non-overlapping ranges
        for severity in 1u8..=10u8 {
            let count = [
                threat_severity::is_low(severity),
                threat_severity::is_medium(severity),
                threat_severity::is_high(severity),
                threat_severity::is_critical(severity),
            ]
            .iter()
            .filter(|&&x| x)
            .count();

            assert_eq!(
                count, 1,
                "Severity {} should be in exactly one category",
                severity
            );
        }
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
            severity: 3,
            confidence: 25,
            description: None,
            source: Text::from("Automated Analysis"),
            first_seen: None,
            last_seen: None,
        };

        let high_confidence = ThreatInfo {
            threat_type: Text::from("malware"),
            severity: 9,
            confidence: 95,
            description: Some(Text::from("Confirmed by multiple sources")),
            source: Text::from("Threat Intelligence Feed"),
            first_seen: Some(1640995200),
            last_seen: Some(1672531200),
        };

        assert!(low_confidence.confidence < 50);
        assert!(high_confidence.confidence > 90);
        assert!(high_confidence.severity > low_confidence.severity);
    }
}
