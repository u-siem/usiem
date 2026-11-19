//! A hash whose output never changes: across runs, builds, platforms and Rust
//! releases.
//!
//! IDs such as [`crate::event::EventId`] are stored next to the events they
//! name and compared again later, possibly by a binary built with another
//! toolchain. `std`'s `DefaultHasher` explicitly does not promise a stable
//! algorithm, so it cannot be used for them. [`StableHasher`] is 64-bit
//! FNV-1a over an explicit byte encoding: every value is written as bytes
//! defined here, never through `std::hash::Hash`, whose output for a type
//! may change between releases.
//!
//! FNV-1a is not collision resistant against an adversary. These IDs are for
//! deduplication and linking, not for integrity.

use crate::event::field::{Ip, Timestamp};
use crate::event::origin::Origin;

const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// 64-bit FNV-1a over an explicit, versionless byte encoding.
///
/// ```
/// use usiem::event::hash::StableHasher;
///
/// let mut h = StableHasher::new();
/// h.write_str("abc");
/// h.write_i64(42);
/// // The value is fixed forever; a change here breaks stored IDs.
/// assert_eq!(h.finish(), StableHasher::new().with_str("abc").with_i64(42).finish());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct StableHasher(u64);

impl StableHasher {
    /// A hasher in its initial state.
    pub const fn new() -> Self {
        Self(OFFSET_BASIS)
    }

    /// Feeds raw bytes, with no length prefix.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(PRIME);
        }
        self.0 = h;
    }

    /// Feeds one byte (used for variant tags).
    pub fn write_u8(&mut self, b: u8) {
        self.write_bytes(&[b]);
    }

    /// Feeds a `u64`, little-endian.
    pub fn write_u64(&mut self, v: u64) {
        self.write_bytes(&v.to_le_bytes());
    }

    /// Feeds an `i64`, little-endian.
    pub fn write_i64(&mut self, v: i64) {
        self.write_bytes(&v.to_le_bytes());
    }

    /// Feeds a string, prefixed with its byte length, so `("ab", "c")` and
    /// `("a", "bc")` hash differently.
    pub fn write_str(&mut self, s: &str) {
        self.write_u64(s.len() as u64);
        self.write_bytes(s.as_bytes());
    }

    /// Feeds an optional string: tag `0` for `None`, tag `1` then the string.
    pub fn write_opt_str(&mut self, s: Option<&str>) {
        match s {
            None => self.write_u8(0),
            Some(s) => {
                self.write_u8(1);
                self.write_str(s);
            }
        }
    }

    /// Feeds a timestamp as its nanoseconds since the epoch.
    pub fn write_timestamp(&mut self, t: Timestamp) {
        self.write_i64(t.as_nanos());
    }

    /// Feeds an address: tag `4` or `6`, then its octets.
    pub fn write_ip(&mut self, ip: &Ip) {
        match ip {
            Ip::V4(v4) => {
                self.write_u8(4);
                self.write_bytes(&v4.octets());
            }
            Ip::V6(v6) => {
                self.write_u8(6);
                self.write_bytes(&v6.octets());
            }
        }
    }

    /// Feeds an [`Origin`]: a tag byte per variant, then its contents.
    pub fn write_origin(&mut self, origin: &Origin) {
        match origin {
            Origin::Ip(ip) => {
                self.write_u8(0);
                self.write_ip(ip);
            }
            Origin::Hostname(s) => {
                self.write_u8(1);
                self.write_str(s);
            }
            Origin::Collector(s) => {
                self.write_u8(2);
                self.write_str(s);
            }
            Origin::File(s) => {
                self.write_u8(3);
                self.write_str(s);
            }
            Origin::Container { id, name, image } => {
                self.write_u8(4);
                self.write_str(id);
                self.write_opt_str(name.as_deref());
                self.write_opt_str(image.as_deref());
            }
        }
    }

    /// Chainable [`StableHasher::write_str`].
    pub fn with_str(mut self, s: &str) -> Self {
        self.write_str(s);
        self
    }

    /// Chainable [`StableHasher::write_i64`].
    pub fn with_i64(mut self, v: i64) -> Self {
        self.write_i64(v);
        self
    }

    /// The hash of everything fed so far.
    pub const fn finish(&self) -> u64 {
        self.0
    }
}

impl Default for StableHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_reference_vectors() {
        // Published FNV-1a 64 test vectors.
        let h = |s: &str| {
            let mut h = StableHasher::new();
            h.write_bytes(s.as_bytes());
            h.finish()
        };
        assert_eq!(h(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(h("a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(h("foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn length_prefix_separates_strings() {
        let a = StableHasher::new().with_str("ab").with_str("c").finish();
        let b = StableHasher::new().with_str("a").with_str("bc").finish();
        assert_ne!(a, b);
    }
}
