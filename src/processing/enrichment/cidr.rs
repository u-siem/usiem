//! An in-memory longest-prefix-match table: [`CidrDataset`].
//!
//! The bundled [`NetworkDataset`] for lists that fit in memory: IP
//! blocklists, threat feeds, site/zone tables. Large external databases
//! (GeoIP `.mmdb` files) implement [`NetworkDataset`] themselves.
//!
//! Lookup probes one hash table per distinct prefix length, longest first.
//! Real feeds use a handful of lengths (`/32`, `/24`, a few aggregates), so a
//! lookup is a few hash probes regardless of how many networks are loaded.

use crate::processing::enrichment::dataset::{
    IpNetwork, NetworkDataset, NetworkDatasetStats, v4_mask, v6_mask,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;

/// Networks of one address family with one prefix length.
#[derive(Debug, Clone)]
struct PrefixTable {
    prefix_len: u8,
    /// Masked network bits → index into `CidrDataset::values`.
    networks: HashMap<u128, usize>,
}

/// Immutable CIDR → value table with longest-prefix lookups.
///
/// Built once from a list of networks; updates build a new table (wrap it in
/// an `Arc` and swap it). When the same network appears twice, the later
/// value wins.
///
/// ```
/// use usiem::processing::enrichment::{CidrDataset, NetworkDataset};
///
/// let table = CidrDataset::from_pairs([
///     ("10.0.0.0/8".parse().unwrap(), "corp"),
///     ("10.1.0.0/16".parse().unwrap(), "lab"),
/// ]);
/// let ip = "10.1.2.3".parse().unwrap();
/// assert_eq!(table.lookup_by_ip(&ip).as_deref(), Some(&"lab"));
/// assert!(table.lookup_by_ip(&"192.0.2.1".parse().unwrap()).is_none());
/// ```
#[derive(Debug, Clone)]
pub struct CidrDataset<V> {
    /// Sorted by prefix length, longest first.
    v4: Vec<PrefixTable>,
    v6: Vec<PrefixTable>,
    values: Vec<V>,
}

impl<V> Default for CidrDataset<V> {
    fn default() -> Self {
        CidrDataset {
            v4: Vec::new(),
            v6: Vec::new(),
            values: Vec::new(),
        }
    }
}

impl<V> CidrDataset<V> {
    /// Builds a table from `(network, value)` pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (IpNetwork, V)>) -> CidrDataset<V> {
        let mut table = CidrDataset::default();
        for (network, value) in pairs {
            table.insert(network, value);
        }
        table
    }

    fn insert(&mut self, network: IpNetwork, value: V) {
        let (tables, bits) = match network {
            IpNetwork::V4 { addr, prefix_len } => (
                &mut self.v4,
                u128::from(u32::from(addr) & v4_mask(prefix_len)),
            ),
            IpNetwork::V6 { addr, prefix_len } => {
                (&mut self.v6, u128::from(addr) & v6_mask(prefix_len))
            }
        };
        let prefix_len = network.prefix_len();
        let position = match tables.binary_search_by(|t| prefix_len.cmp(&t.prefix_len)) {
            Ok(i) => i,
            Err(i) => {
                tables.insert(
                    i,
                    PrefixTable {
                        prefix_len,
                        networks: HashMap::new(),
                    },
                );
                i
            }
        };
        let table = &mut tables[position];
        match table.networks.get(&bits) {
            Some(&index) => self.values[index] = value,
            None => {
                table.networks.insert(bits, self.values.len());
                self.values.push(value);
            }
        }
    }

    /// The value of the most specific network containing `ip`.
    pub fn get(&self, ip: &IpAddr) -> Option<&V> {
        let (tables, bits) = match ip {
            IpAddr::V4(v4) => (&self.v4, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => return self.get(&IpAddr::V4(v4)),
                None => (&self.v6, u128::from(*v6)),
            },
        };
        let is_v4 = ip.is_ipv4();
        tables.iter().find_map(|table| {
            let mask = if is_v4 {
                u128::from(v4_mask(table.prefix_len))
            } else {
                v6_mask(table.prefix_len)
            };
            table
                .networks
                .get(&(bits & mask))
                .map(|&index| &self.values[index])
        })
    }

    /// Number of distinct networks.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl<V> NetworkDataset<V> for CidrDataset<V>
where
    V: Clone + Send + Sync + 'static,
{
    fn lookup_by_ip(&self, ip: &IpAddr) -> Option<Cow<'_, V>> {
        self.get(ip).map(Cow::Borrowed)
    }

    fn is_empty(&self) -> bool {
        CidrDataset::is_empty(self)
    }

    fn network_count(&self) -> usize {
        self.len()
    }

    fn get_stats(&self) -> NetworkDatasetStats {
        NetworkDatasetStats {
            network_count: self.len(),
            is_empty: CidrDataset::is_empty(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNetwork {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let table = CidrDataset::from_pairs([
            (net("0.0.0.0/0"), "any"),
            (net("10.0.0.0/8"), "ten"),
            (net("10.20.0.0/16"), "lab"),
            (net("10.20.30.40"), "host"),
        ]);
        assert_eq!(table.get(&ip("10.20.30.40")), Some(&"host"));
        assert_eq!(table.get(&ip("10.20.30.41")), Some(&"lab"));
        assert_eq!(table.get(&ip("10.99.0.1")), Some(&"ten"));
        assert_eq!(table.get(&ip("192.0.2.1")), Some(&"any"));
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn host_bits_are_ignored_and_duplicates_replace() {
        let table =
            CidrDataset::from_pairs([(net("192.168.1.77/24"), 1), (net("192.168.1.0/24"), 2)]);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&ip("192.168.1.200")), Some(&2));
        assert_eq!(table.get(&ip("192.168.2.1")), None);
    }

    #[test]
    fn ipv6_and_mapped_ipv4() {
        let table = CidrDataset::from_pairs([
            (net("2001:db8::/32"), "doc"),
            (net("2001:db8:1::/48"), "doc-1"),
            (net("203.0.113.0/24"), "test-net-3"),
        ]);
        assert_eq!(table.get(&ip("2001:db8:1::5")), Some(&"doc-1"));
        assert_eq!(table.get(&ip("2001:db8:2::5")), Some(&"doc"));
        assert_eq!(table.get(&ip("2001:db9::1")), None);
        assert_eq!(table.get(&ip("::ffff:203.0.113.9")), Some(&"test-net-3"));
        // IPv4 networks never match plain IPv6 addresses.
        assert_eq!(table.get(&ip("::cb00:7109")), None);
    }

    #[test]
    fn empty_table_and_trait_object() {
        let table: CidrDataset<u8> = CidrDataset::default();
        assert!(table.is_empty());
        let dataset: &dyn NetworkDataset<u8> = &table;
        assert!(dataset.lookup_by_ip(&ip("10.0.0.1")).is_none());
        assert_eq!(dataset.network_count(), 0);
    }

    #[test]
    fn parses_networks() {
        assert_eq!(net("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert_eq!(net("10.1.2.3").to_string(), "10.1.2.3/32");
        assert_eq!(net("2001:db8::1/32").to_string(), "2001:db8::/32");
        assert!("10.0.0.0/33".parse::<IpNetwork>().is_err());
        assert!("nope/8".parse::<IpNetwork>().is_err());
    }
}
