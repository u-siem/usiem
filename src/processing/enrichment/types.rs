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
//! - Include severity/risk scores using standard scales (1-10, 0-100)
//! - Support temporal data with Unix timestamps for interoperability
//! - Implement `Clone` and `Debug` for usability in the enrichment system

use crate::event::field::Text;

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
/// # Severity Scale
///
/// The severity field uses a 1-10 scale where:
/// - **1-3**: Low severity (informational, suspicious activity)
/// - **4-6**: Medium severity (likely malicious, increased monitoring)
/// - **7-9**: High severity (confirmed malicious, immediate action)
/// - **10**: Critical severity (active attack, emergency response)
///
/// # Confidence Scale  
///
/// The confidence field uses a 0-100 scale representing:
/// - **0-25**: Low confidence (unverified, single source)
/// - **26-50**: Medium confidence (some verification, multiple sources)
/// - **51-75**: High confidence (well-verified, reputable sources)
/// - **76-100**: Very high confidence (confirmed, authoritative sources)
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
///     severity: 8,  // High severity
///     confidence: 85,  // Very high confidence
///     description: Some(Text::from("Mirai botnet C&C server")),
///     source: Text::from("SecurityVendor ThreatFeed v2.1"),
///     first_seen: Some(1640995200), // Unix timestamp
///     last_seen: Some(1672531200),  // Unix timestamp
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    /// Type of threat (e.g., "malware", "phishing", "botnet", "scanner")
    pub threat_type: Text,

    /// Threat severity on a 1-10 scale (1=low, 10=critical)
    pub severity: u8,

    /// Confidence level in the assessment (0-100 scale, 100=highest confidence)
    pub confidence: u8,

    /// Human-readable description of the threat
    pub description: Option<Text>,

    /// Source of the threat intelligence (vendor, feed name, version)
    pub source: Text,

    /// When this indicator was first observed (Unix timestamp)
    pub first_seen: Option<u64>,

    /// When this indicator was last observed (Unix timestamp)  
    pub last_seen: Option<u64>,
}

impl Default for ThreatInfo {
    fn default() -> Self {
        Self {
            threat_type: Text::from("unknown"),
            severity: 1,
            confidence: 0,
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
/// # Criticality Scale
///
/// The criticality field uses a 1-10 scale representing business impact:
/// - **1-2**: Non-critical (development, testing, personal devices)
/// - **3-4**: Low criticality (internal tools, backup systems)
/// - **5-6**: Medium criticality (business applications, shared resources)
/// - **7-8**: High criticality (production systems, customer-facing services)
/// - **9-10**: Critical (core infrastructure, revenue-generating systems)
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
///     criticality: 9,  // Critical system
///     location: Some(Text::from("DataCenter-East-Rack42")),
///     tags: vec![
///         Text::from("production"),
///         Text::from("web-server"),
///         Text::from("customer-facing"),
///     ],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct AssetInfo {
    /// Type of asset (e.g., "server", "workstation", "network_device")
    pub asset_type: Text,

    /// Owner or responsible team/person for this asset
    pub owner: Option<Text>,

    /// Business criticality on a 1-10 scale (1=non-critical, 10=critical)
    pub criticality: u8,

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
/// # Risk Score Scale
///
/// The risk_score field uses a 1-10 scale representing security risk:
/// - **1-2**: Very low risk (standard users, limited access)
/// - **3-4**: Low risk (regular employees, standard permissions)
/// - **5-6**: Medium risk (power users, some elevated access)
/// - **7-8**: High risk (administrators, sensitive data access)
/// - **9-10**: Very high risk (privileged accounts, critical system access)
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
///     risk_score: 6,  // Medium risk (developer with some access)
///     is_privileged: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct UserProfile {
    /// Full name of the user
    pub full_name: Option<Text>,

    /// Department or organizational unit
    pub department: Option<Text>,

    /// Job title or role within the organization
    pub role: Option<Text>,

    /// Security risk score on a 1-10 scale (1=low risk, 10=high risk)
    pub risk_score: u8,

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
        assert_eq!(threat.severity, 1);
        assert_eq!(threat.confidence, 0);
        assert!(threat.description.is_none());
        assert_eq!(threat.source.to_string(), "unknown");
        assert!(threat.first_seen.is_none());
        assert!(threat.last_seen.is_none());
    }

    #[test]
    fn test_threat_info_with_data() {
        let threat = ThreatInfo {
            threat_type: Text::from("malware"),
            severity: 8,
            confidence: 85,
            description: Some(Text::from("Known botnet C&C server")),
            source: Text::from("ThreatIntel Feed v2.1"),
            first_seen: Some(1640995200),
            last_seen: Some(1672531200),
        };

        assert_eq!(threat.threat_type.to_string(), "malware");
        assert_eq!(threat.severity, 8);
        assert_eq!(threat.confidence, 85);
        assert_eq!(
            threat.description.as_ref().unwrap().to_string(),
            "Known botnet C&C server"
        );
        assert_eq!(threat.source.to_string(), "ThreatIntel Feed v2.1");
        assert_eq!(threat.first_seen.unwrap(), 1640995200);
        assert_eq!(threat.last_seen.unwrap(), 1672531200);
    }

    #[test]
    fn test_asset_info_creation() {
        let asset = AssetInfo {
            asset_type: Text::from("server"),
            owner: Some(Text::from("IT Operations Team")),
            criticality: 9,
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
        assert_eq!(asset.criticality, 9);
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
            risk_score: 6,
            is_privileged: false,
        };

        assert_eq!(user.full_name.as_ref().unwrap().to_string(), "John Smith");
        assert_eq!(user.department.as_ref().unwrap().to_string(), "Engineering");
        assert_eq!(
            user.role.as_ref().unwrap().to_string(),
            "Senior Software Engineer"
        );
        assert_eq!(user.risk_score, 6);
        assert!(!user.is_privileged);
    }

    #[test]
    fn test_user_profile_privileged() {
        let admin_user = UserProfile {
            full_name: Some(Text::from("Admin User")),
            department: Some(Text::from("IT Security")),
            role: Some(Text::from("System Administrator")),
            risk_score: 9,
            is_privileged: true,
        };

        assert_eq!(admin_user.risk_score, 9);
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
            criticality: 1,
            location: None,
            tags: vec![],
        };
        let _asset_clone = asset.clone();

        let user = UserProfile {
            full_name: None,
            department: None,
            role: None,
            risk_score: 1,
            is_privileged: false,
        };
        let _user_clone = user.clone();
    }
}
