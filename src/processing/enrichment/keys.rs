//! Dataset key types for strongly-typed enrichment access

use crate::event::field::{Ip, Text};
use crate::processing::enrichment::core::DatasetKey;
use crate::processing::enrichment::dataset::TypedDataset;
use crate::processing::enrichment::types::{AssetInfo, GeoIp, ThreatInfo, UserProfile};

/// Key type for GeoIP dataset
pub struct GeoIpKey;

impl DatasetKey for GeoIpKey {
    type Key = Ip;
    type Value = GeoIp;
    type Dataset = TypedDataset<Ip, GeoIp>;

    const NAME: &'static str = "geoip";
}

/// Key type for threat intelligence IP dataset
pub struct ThreatIpKey;

impl DatasetKey for ThreatIpKey {
    type Key = Ip;
    type Value = ThreatInfo;
    type Dataset = TypedDataset<Ip, ThreatInfo>;

    const NAME: &'static str = "threat_ip";
}

/// Key type for asset information dataset
pub struct AssetKey;

impl DatasetKey for AssetKey {
    type Key = Text;
    type Value = AssetInfo;
    type Dataset = TypedDataset<Text, AssetInfo>;

    const NAME: &'static str = "assets";
}

/// Key type for user profile dataset
pub struct UserKey;

impl DatasetKey for UserKey {
    type Key = Text;
    type Value = UserProfile;
    type Dataset = TypedDataset<Text, UserProfile>;

    const NAME: &'static str = "users";
}
