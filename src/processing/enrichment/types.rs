//! Built-in enrichment value types.
//!
//! Only [`GeoIp`] lives here: it is the value type of [`super::GeoIpDataset`],
//! the one provider interface shared across crates (a MaxMind/mmdb reader
//! implements it). Other context (assets, users, threat indicators) differs
//! per deployment, so applications define their own value types and plug
//! them into [`super::MapDataset`]/[`super::CidrDataset`]/[`super::NetworkDataset`].

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
}
