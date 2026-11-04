//! Built-in enrichment value types for common SIEM use cases
//!
//! This module provides standard data structures for common enrichment scenarios
//! in security information and event management (SIEM) systems. These types are
//! designed to be:
//!
//! - **Comprehensive** - Cover the most common enrichment data needs
//! - **Extensible** - Allow for optional fields and future expansion
//! - **Efficient** - Use appropriate data types for performance
//! - **Interoperable** - Compatible with external data sources and formats
//!
//! # Available Types
//!
//! * [`GeoIp`] - Geographic and network information for IP addresses
//! * [`ThreatInfo`] - Threat intelligence data with severity and confidence
//! * [`AssetInfo`] - Asset management and inventory information
//! * [`UserProfile`] - User identity and risk profile information
//!
//! # Design Principles
//!
//! All types follow consistent design principles:
//! - Use `Option<T>` for fields that may be missing from data sources
//! - Use `Text` type for string data to maintain consistency with the event system
//! - Ratings use the shared scales in [`crate::processing::rating`]:
//!   [`Severity`] (and its [`Criticality`]/[`RiskLevel`] aliases) and
//!   [`Confidence`], the same types a [`crate::processing::signal::Signal`]
//!   carries, so a lookup result feeds a signal without conversion
//! - Dates are [`Timestamp`]s, usiem's one datetime type
//! - Implement `Clone` and `Debug` for usability in the enrichment system

use crate::event::field::{Text, Timestamp};
use crate::processing::rating::{Confidence, Criticality, RiskLevel, Severity};

/// Geographic and network information for IP addresses
///
/// This structure contains comprehensive geographic and network operator
/// information that can be associated with IP addresses. It's designed to
/// be compatible with popular GeoIP databases like MaxMind GeoIP2, IP2Location,
/// and other commercial and open-source providers.
///
/// # Field Descriptions
///
/// * `country_code` - ISO 3166-1 alpha-2 country code (e.g., "US", "GB", "DE")
/// * `country` - Full country name (e.g., "United States", "Germany")
/// * `city` - City name where the IP is located
/// * `latitude`/`longitude` - Geographic coordinates (WGS84 decimal degrees)
/// * `asn` - Autonomous System Number identifying the network operator
/// * `organization` - Organization name associated with the ASN
/// * `isp` - Internet Service Provider name (may differ from organization)
///
/// # Usage Examples
///
/// ```rust,no_compile,no_run
/// let geo = GeoIp {
///     country_code: Some(Text::from("US")),
///     country: Some(Text::from("United States")),
///     city: Some(Text::from("San Francisco")),
///     latitude: Some(37.7749),
///     longitude: Some(-122.4194),
///     asn: Some(13335),
///     organization: Some(Text::from("Cloudflare, Inc.")),
///     isp: Some(Text::from("Cloudflare")),
/// };
/// ```
///
/// # Data Source Compatibility
///
/// This structure is designed to accommodate data from various sources:
/// - **MaxMind GeoIP2** - Maps directly to City and ISP databases
/// - **IP2Location** - Compatible with most database versions
/// - **IPinfo** - Supports their API response format
/// - **Custom sources** - Flexible optional fields for any provider
#[derive(Debug, Clone, Default)]
pub struct GeoIp {
    /// ISO 3166-1 alpha-2 country code (2-letter code like "US", "GB")
    pub country_code: Option<Text>,

    /// Full country name in English
    pub country: Option<Text>,

    /// City name where the IP address is located
    pub city: Option<Text>,

    /// Latitude coordinate in decimal degrees (WGS84)
    pub latitude: Option<f64>,

    /// Longitude coordinate in decimal degrees (WGS84)
    pub longitude: Option<f64>,

    /// Autonomous System Number (ASN) of the network operator
    pub asn: Option<u32>,

    /// Organization name associated with the ASN
    pub organization: Option<Text>,

    /// Internet Service Provider name (may differ from organization)
    pub isp: Option<Text>,
}

/// Threat intelligence information for IP addresses and other indicators
///
/// This structure represents threat intelligence data from various sources
/// including commercial threat feeds, open source intelligence (OSINT),
/// internal security research, and collaborative sharing platforms.
///
/// # Ratings
///
/// - `severity` is a [`Severity`]: `Low` (informational, suspicious),
///   `Medium` (likely malicious), `High` (confirmed malicious) or `Critical`
///   (active attack). Feeds that score 1-10 convert with
///   [`Severity::from_score`].
/// - `confidence` is a [`Confidence`] percentage: roughly 0-25 unverified,
///   26-50 some verification, 51-75 well verified, 76-100 confirmed by
///   authoritative sources.
/// - `first_seen`/`last_seen` are [`Timestamp`]s (UTC).
///
/// # Common Threat Types
///
/// * `malware` - Known malware command & control servers
/// * `phishing` - Phishing and fraud-related infrastructure
/// * `botnet` - Botnet command & control servers
/// * `scanner` - Port scanners and reconnaissance tools
/// * `spam` - Email spam sources and open relays
/// * `proxy` - Malicious proxy servers and anonymization services
/// * `apt` - Advanced Persistent Threat (APT) infrastructure
///
/// # Usage Example
///
/// ```rust,no_compile,no_run
/// let threat = ThreatInfo {
///     threat_type: Text::from("botnet"),
///     severity: Severity::High,
///     confidence: Confidence::new(85),
///     description: Some(Text::from("Mirai botnet C&C server")),
///     source: Text::from("SecurityVendor ThreatFeed v2.1"),
///     first_seen: Some(Timestamp::from_secs(1640995200)),
///     last_seen: Some(Timestamp::from_secs(1672531200)),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatInfo {
    /// Type of threat (e.g., "malware", "phishing", "botnet", "scanner")
    pub threat_type: Text,

    /// How bad the threat is
    pub severity: Severity,

    /// How sure the source is of the assessment
    pub confidence: Confidence,

    /// Human-readable description of the threat
    pub description: Option<Text>,

    /// Source of the threat intelligence (vendor, feed name, version)
    pub source: Text,

    /// When this indicator was first observed
    pub first_seen: Option<Timestamp>,

    /// When this indicator was last observed
    pub last_seen: Option<Timestamp>,
}

impl ThreatInfo {
    /// Whether this threat is at least as severe as `level`.
    pub fn is_at_least(&self, level: Severity) -> bool {
        self.severity >= level
    }
}

impl Default for ThreatInfo {
    fn default() -> Self {
        Self {
            threat_type: Text::from("unknown"),
            severity: Severity::Low,
            confidence: Confidence::NONE,
            description: None,
            source: Text::from("unknown"),
            first_seen: None,
            last_seen: None,
        }
    }
}

/// Asset management and inventory information
///
/// This structure represents information about IT assets (servers, workstations,
/// network devices, etc.) that can be used to enrich security events with
/// contextual information about the affected systems.
///
/// # Criticality
///
/// `criticality` is a [`Criticality`] (the [`Severity`] scale) for
/// business impact:
/// - **Low**: development, testing, personal devices
/// - **Medium**: internal tools, business applications, shared resources
/// - **High**: production systems, customer-facing services
/// - **Critical**: core infrastructure, revenue-generating systems
///
/// # Common Asset Types
///
/// * `server` - Physical or virtual servers
/// * `workstation` - End-user computers and laptops
/// * `network_device` - Routers, switches, firewalls
/// * `mobile_device` - Smartphones, tablets
/// * `iot_device` - Internet of Things devices
/// * `database` - Database servers and instances
/// * `web_service` - Web applications and APIs
///
/// # Usage Example
///
/// ```rust,no_compile,no_run
/// let asset = AssetInfo {
///     asset_type: Text::from("server"),
///     owner: Some(Text::from("IT Operations Team")),
///     criticality: Criticality::Critical,
///     location: Some(Text::from("DataCenter-East-Rack42")),
///     tags: vec![
///         Text::from("production"),
///         Text::from("web-server"),
///         Text::from("customer-facing"),
///     ],
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AssetInfo {
    /// Type of asset (e.g., "server", "workstation", "network_device")
    pub asset_type: Text,

    /// Owner or responsible team/person for this asset
    pub owner: Option<Text>,

    /// Business impact if this asset is compromised
    pub criticality: Criticality,

    /// Physical or logical location of the asset
    pub location: Option<Text>,

    /// Flexible tags for categorization and filtering
    pub tags: Vec<Text>,
}

/// User identity and risk profile information
///
/// This structure contains user information that can be used to enrich
/// security events with context about the users involved. It includes
/// both identity information and risk assessment data for security analysis.
///
/// # Risk Level
///
/// `risk_score` is a [`RiskLevel`] (the [`Severity`] scale) for account
/// risk:
/// - **Low**: standard users, limited access
/// - **Medium**: power users, some elevated access
/// - **High**: administrators, sensitive data access
/// - **Critical**: privileged accounts with critical system access
///
/// # Privileged Account Classification
///
/// The `is_privileged` flag indicates whether the account has elevated
/// permissions that could be used to compromise systems or access sensitive
/// data. This includes:
/// - Administrative accounts (domain admin, local admin)
/// - Service accounts with elevated permissions
/// - Developer accounts with production access
/// - Security team accounts with monitoring privileges
///
/// # Data Sources
///
/// This information typically comes from:
/// - **LDAP/Active Directory** - Identity and organizational information
/// - **HR systems** - Employee details and organizational structure
/// - **IAM systems** - Role and permission information
/// - **Risk assessment tools** - Calculated risk scores based on behavior
///
/// # Usage Example
///
/// ```rust,no_compile,no_run
/// let user = UserProfile {
///     full_name: Some(Text::from("John Smith")),
///     department: Some(Text::from("Engineering")),
///     role: Some(Text::from("Senior Software Engineer")),
///     risk_score: RiskLevel::Medium, // developer with some access
///     is_privileged: false,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct UserProfile {
    /// Full name of the user
    pub full_name: Option<Text>,

    /// Department or organizational unit
    pub department: Option<Text>,

    /// Job title or role within the organization
    pub role: Option<Text>,

    /// Security risk of this account
    pub risk_score: RiskLevel,

    /// Whether this is a privileged account with elevated permissions
    pub is_privileged: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_default() {
        let geo = GeoIp::default();

        assert!(geo.country_code.is_none());
        assert!(geo.country.is_none());
        assert!(geo.city.is_none());
        assert!(geo.latitude.is_none());
        assert!(geo.longitude.is_none());
        assert!(geo.asn.is_none());
        assert!(geo.organization.is_none());
        assert!(geo.isp.is_none());
    }

    #[test]
    fn test_geoip_with_data() {
        let geo = GeoIp {
            country_code: Some(Text::from("US")),
            country: Some(Text::from("United States")),
            city: Some(Text::from("San Francisco")),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            asn: Some(13335),
            organization: Some(Text::from("Cloudflare, Inc.")),
            isp: Some(Text::from("Cloudflare")),
        };

        assert_eq!(geo.country_code.as_ref().unwrap().to_string(), "US");
        assert_eq!(geo.country.as_ref().unwrap().to_string(), "United States");
        assert_eq!(geo.city.as_ref().unwrap().to_string(), "San Francisco");
        assert_eq!(geo.latitude.unwrap(), 37.7749);
        assert_eq!(geo.longitude.unwrap(), -122.4194);
        assert_eq!(geo.asn.unwrap(), 13335);
        assert_eq!(
            geo.organization.as_ref().unwrap().to_string(),
            "Cloudflare, Inc."
        );
        assert_eq!(geo.isp.as_ref().unwrap().to_string(), "Cloudflare");
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
    fn test_threat_info_with_data() {
        let threat = ThreatInfo {
            threat_type: Text::from("malware"),
            severity: Severity::High,
            confidence: Confidence::new(85),
            description: Some(Text::from("Known botnet C&C server")),
            source: Text::from("ThreatIntel Feed v2.1"),
            first_seen: Some(Timestamp::from_secs(1640995200)),
            last_seen: Some(Timestamp::from_secs(1672531200)),
        };

        assert_eq!(threat.threat_type.to_string(), "malware");
        assert_eq!(threat.severity, Severity::High);
        assert_eq!(threat.confidence.as_percent(), 85);
        assert!(threat.is_at_least(Severity::Medium));
        assert!(threat.is_at_least(Severity::High));
        assert!(!threat.is_at_least(Severity::Critical));
        assert_eq!(
            threat.description.as_ref().unwrap().to_string(),
            "Known botnet C&C server"
        );
        assert_eq!(threat.source.to_string(), "ThreatIntel Feed v2.1");
        assert_eq!(threat.first_seen.unwrap().as_secs(), 1640995200);
        assert!(threat.first_seen < threat.last_seen);
    }

    #[test]
    fn test_asset_info_creation() {
        let asset = AssetInfo {
            asset_type: Text::from("server"),
            owner: Some(Text::from("IT Operations Team")),
            criticality: Criticality::Critical,
            location: Some(Text::from("DataCenter-East-Rack42")),
            tags: vec![
                Text::from("production"),
                Text::from("web-server"),
                Text::from("customer-facing"),
            ],
        };

        assert_eq!(asset.asset_type.to_string(), "server");
        assert_eq!(
            asset.owner.as_ref().unwrap().to_string(),
            "IT Operations Team"
        );
        assert_eq!(asset.criticality, Criticality::Critical);
        assert_eq!(
            asset.location.as_ref().unwrap().to_string(),
            "DataCenter-East-Rack42"
        );
        assert_eq!(asset.tags.len(), 3);
        assert_eq!(asset.tags[0].to_string(), "production");
        assert_eq!(asset.tags[1].to_string(), "web-server");
        assert_eq!(asset.tags[2].to_string(), "customer-facing");
    }

    #[test]
    fn test_user_profile_creation() {
        let user = UserProfile {
            full_name: Some(Text::from("John Smith")),
            department: Some(Text::from("Engineering")),
            role: Some(Text::from("Senior Software Engineer")),
            risk_score: RiskLevel::Medium,
            is_privileged: false,
        };

        assert_eq!(user.full_name.as_ref().unwrap().to_string(), "John Smith");
        assert_eq!(user.department.as_ref().unwrap().to_string(), "Engineering");
        assert_eq!(
            user.role.as_ref().unwrap().to_string(),
            "Senior Software Engineer"
        );
        assert_eq!(user.risk_score, RiskLevel::Medium);
        assert!(!user.is_privileged);
    }

    #[test]
    fn test_user_profile_privileged() {
        let admin_user = UserProfile {
            full_name: Some(Text::from("Admin User")),
            department: Some(Text::from("IT Security")),
            role: Some(Text::from("System Administrator")),
            risk_score: RiskLevel::Critical,
            is_privileged: true,
        };

        assert_eq!(admin_user.risk_score, RiskLevel::Critical);
        assert!(admin_user.is_privileged);
    }

    #[test]
    fn test_types_are_cloneable() {
        let geo = GeoIp::default();
        let _geo_clone = geo.clone();

        let threat = ThreatInfo::default();
        let _threat_clone = threat.clone();

        let asset = AssetInfo {
            asset_type: Text::from("test"),
            owner: None,
            criticality: Criticality::Low,
            location: None,
            tags: vec![],
        };
        let _asset_clone = asset.clone();

        let user = UserProfile {
            full_name: None,
            department: None,
            role: None,
            risk_score: RiskLevel::Low,
            is_privileged: false,
        };
        let _user_clone = user.clone();
    }
}
