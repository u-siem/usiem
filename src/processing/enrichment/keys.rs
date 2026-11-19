//! Dataset key types for strongly-typed enrichment access

use crate::event::field::Ip;
use crate::processing::enrichment::core::DatasetKey;
use crate::processing::enrichment::dataset::MapDataset;
use crate::processing::enrichment::types::GeoIp;

/// Key type for GeoIP dataset
pub struct GeoIpKey;

impl DatasetKey for GeoIpKey {
    type Key = Ip;
    type Value = GeoIp;
    type Dataset = MapDataset<Ip, GeoIp>;

    const NAME: &'static str = "geoip";
}
