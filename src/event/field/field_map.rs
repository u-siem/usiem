//! [`FieldMap`]: a named bag of [`FieldValue`]s with ergonomic read access —
//! the same role [`crate::event::field::ObjectBuilder`] plays on the write
//! side, but keyed by [`Text`] (not `String`) so a literal key like
//! `"ip"`/`"query"` costs no allocation, and with a curated read-only API
//! (no `Deref`/`DerefMut`) rather than exposing the backing store
//! wholesale — mirroring `ObjectBuilder`'s own existing precedent for this
//! exact "bag of fields" role.
//!
//! Not scoped to any one subsystem: [`crate::processing::action::Action`]
//! is `FieldMap`'s first consumer (for invocation params and
//! [`crate::processing::action::ActionOutcome`]'s result data), but nothing
//! here is Action-specific.
//!
//! # Why `SmallVec`, not `HashMap`
//!
//! Typical param/result-data counts are 1-5 entries. At that size, a linear
//! scan over an association list beats hashing (no hash computation, no
//! bucket indirection, better cache locality), and avoiding the `HashMap`
//! table's own allocation matters for a type constructed on every action
//! invocation. `insert` is therefore O(n) (scan for an existing key before
//! replacing/pushing) rather than O(1) amortized — a deliberate, documented
//! tradeoff that only pays off at this size; don't grow a `FieldMap` to
//! hundreds of entries expecting hash-map performance.

use super::builder::ObjectBuilder;
use super::field_value::FieldValue;
use super::getter::FieldGetter;
use super::text::Text;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::HashMap;

/// Read-only point-lookup capability: "a bag of fields I can look one up in
/// by name." This is the minimal shape [`crate::event::schema::Schema`]'s
/// validator needs from an input field map — it only ever does `.get(name)`
/// for each of *its own* declared fields, never iterates the input map
/// itself, so it doesn't need `Hash`/`Eq`/iteration on the map's key type
/// at all. Implemented for both plain `HashMap`s (so `Event`'s `String`-
/// keyed top-level fields and `FieldValue::Object`'s `Text`-keyed nested
/// maps both work) and for [`FieldMap`].
pub trait FieldLookup {
    fn get(&self, key: &str) -> Option<&FieldValue>;
}

impl<K> FieldLookup for HashMap<K, FieldValue>
where
    K: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    fn get(&self, key: &str) -> Option<&FieldValue> {
        HashMap::get(self, key)
    }
}

impl FieldLookup for FieldMap {
    fn get(&self, key: &str) -> Option<&FieldValue> {
        FieldMap::get(self, key)
    }
}

/// A named bag of [`FieldValue`]s, keyed by [`Text`] for allocation-free
/// literal keys. See the module docs for why this has a curated API rather
/// than `Deref`ing to its backing storage, and why that storage is a
/// `SmallVec` of pairs rather than a `HashMap`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FieldMap(SmallVec<[(Text, FieldValue); 4]>);

impl FieldMap {
    /// Create a new, empty `FieldMap`.
    pub fn new() -> Self {
        Self(SmallVec::new())
    }

    /// Get a field by name.
    pub fn get(&self, key: &str) -> Option<&FieldValue> {
        self.0
            .iter()
            .find(|(k, _)| {
                let k: &str = k.as_ref();
                k == key
            })
            .map(|(_, v)| v)
    }

    /// Check whether a field is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// A fluent [`FieldGetter`] for `key`, for ergonomic type conversion and
    /// string-utility chaining (`.as_str()`, `.as_u64_or(default)`,
    /// `.contains(..)`, ...).
    ///
    /// Unlike [`ObjectBuilder::getter`], this never allocates: `key` is
    /// already borrowed for at least as long as the returned
    /// [`FieldGetter`], so its `path` can be `Cow::Borrowed` directly
    /// instead of being forced through an owned copy.
    pub fn getter<'a>(&'a self, key: &'a str) -> FieldGetter<'a> {
        FieldGetter {
            field: self.get(key),
            path: Cow::Borrowed(key),
        }
    }

    /// Insert a field, converting `key`/`value` automatically. Replaces and
    /// returns the previous value if `key` was already present — the same
    /// "last write wins" semantics a `HashMap` has, just found via a linear
    /// scan instead of a hash lookup.
    pub fn insert(
        &mut self,
        key: impl Into<Text>,
        value: impl Into<FieldValue>,
    ) -> Option<FieldValue> {
        let key = key.into();
        let value = value.into();
        if let Some(existing) = self.0.iter_mut().find(|(k, _)| *k == key) {
            Some(std::mem::replace(&mut existing.1, value))
        } else {
            self.0.push((key, value));
            None
        }
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this map has no fields.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over `(name, value)` pairs.
    pub fn iter(&self) -> FieldMapIter<'_> {
        FieldMapIter {
            inner: self.0.iter(),
        }
    }

    /// Consume this `FieldMap`, building a fresh `HashMap` from its
    /// entries. A real allocation (unlike the old `HashMap`-backed
    /// `FieldMap`, there's no `HashMap` living inside this one to move
    /// out) — fine at the audit/output boundary this is used for (e.g.
    /// [`crate::processing::action::ActionOutcome::into_event`] embedding
    /// a `FieldMap` into a `FieldValue::Object`), not on the hot param-
    /// passing path.
    pub fn into_map(self) -> HashMap<Text, FieldValue> {
        self.0.into_iter().collect()
    }
}

impl IntoIterator for FieldMap {
    type Item = (Text, FieldValue);
    type IntoIter = smallvec::IntoIter<[(Text, FieldValue); 4]>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Iterator over a [`FieldMap`]'s `(name, value)` pairs, returned by
/// [`FieldMap::iter`] and `IntoIterator for &FieldMap`. A named type
/// (rather than `impl Iterator`/`std::iter::Map`) so it can appear as an
/// associated type.
pub struct FieldMapIter<'a> {
    inner: std::slice::Iter<'a, (Text, FieldValue)>,
}

impl<'a> Iterator for FieldMapIter<'a> {
    type Item = (&'a Text, &'a FieldValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k, v))
    }
}

impl<'a> IntoIterator for &'a FieldMap {
    type Item = (&'a Text, &'a FieldValue);
    type IntoIter = FieldMapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K: Into<Text>, V: Into<FieldValue>> FromIterator<(K, V)> for FieldMap {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        // Built via `insert`, not a raw `.collect()` into the SmallVec, so
        // duplicate keys preserve "last write wins" — the same semantics
        // the previous HashMap-backed FieldMap had. A direct collect would
        // silently keep every duplicate instead of deduplicating.
        let mut map = Self::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

impl From<ObjectBuilder> for FieldMap {
    fn from(builder: ObjectBuilder) -> Self {
        builder.into_map().into_iter().collect()
    }
}

impl From<HashMap<Text, FieldValue>> for FieldMap {
    fn from(map: HashMap<Text, FieldValue>) -> Self {
        map.into_iter().collect()
    }
}

impl From<FieldMap> for HashMap<Text, FieldValue> {
    fn from(map: FieldMap) -> Self {
        map.into_map()
    }
}

impl From<FieldMap> for FieldValue {
    fn from(map: FieldMap) -> Self {
        FieldValue::Object(map.into_map())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_and_insert_round_trip() {
        let mut map = FieldMap::new();
        assert_eq!(map.insert("ip", FieldValue::str("203.0.113.5")), None);
        assert_eq!(map.get("ip"), Some(&FieldValue::str("203.0.113.5")));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_insert_replaces_existing_key_and_returns_old_value() {
        let mut map = FieldMap::new();
        map.insert("ip", FieldValue::str("203.0.113.5"));
        let previous = map.insert("ip", FieldValue::str("198.51.100.9"));

        assert_eq!(previous, Some(FieldValue::str("203.0.113.5")));
        assert_eq!(map.get("ip"), Some(&FieldValue::str("198.51.100.9")));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_contains_key() {
        let mut map = FieldMap::new();
        map.insert("ip", FieldValue::str("203.0.113.5"));
        assert!(map.contains_key("ip"));
        assert!(!map.contains_key("missing"));
    }

    #[test]
    fn test_getter_on_present_and_missing_key() {
        let mut map = FieldMap::new();
        map.insert("ip", FieldValue::str("203.0.113.5"));
        map.insert("limit", FieldValue::uint(10));

        assert_eq!(map.getter("ip").as_str(), Some("203.0.113.5"));
        assert_eq!(map.getter("limit").as_u64_or(50), 10);
        assert_eq!(map.getter("missing").as_u64_or(50), 50);
        assert!(map.getter("missing").is_missing());
    }

    #[test]
    fn test_from_iterator_of_static_str_keys() {
        let map: FieldMap = [
            ("ip", FieldValue::str("203.0.113.5")),
            ("query", FieldValue::str("failed login")),
        ]
        .into_iter()
        .collect();

        assert_eq!(map.len(), 2);
        assert_eq!(map.get("ip"), Some(&FieldValue::str("203.0.113.5")));
    }

    #[test]
    fn test_from_iterator_with_duplicate_keys_keeps_last_value() {
        let map: FieldMap = [
            ("ip", FieldValue::str("203.0.113.5")),
            ("ip", FieldValue::str("198.51.100.9")),
        ]
        .into_iter()
        .collect();

        assert_eq!(map.len(), 1);
        assert_eq!(map.get("ip"), Some(&FieldValue::str("198.51.100.9")));
    }

    #[test]
    fn test_from_object_builder() {
        let builder = ObjectBuilder::new()
            .str("ip", "203.0.113.5")
            .uint("ttl", 60);
        let map: FieldMap = builder.into();

        assert_eq!(map.get("ip"), Some(&FieldValue::str("203.0.113.5")));
        assert_eq!(map.get("ttl"), Some(&FieldValue::uint(60)));
    }

    #[test]
    fn test_into_map_produces_an_equivalent_hash_map() {
        let mut map = FieldMap::new();
        map.insert("ip", FieldValue::str("203.0.113.5"));

        let raw = map.into_map();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw.get("ip"), Some(&FieldValue::str("203.0.113.5")));
    }

    #[test]
    fn test_is_empty() {
        let map = FieldMap::new();
        assert!(map.is_empty());
    }

    #[test]
    fn field_lookup_finds_present_keys_and_returns_none_for_absent_ones() {
        let mut map = FieldMap::new();
        map.insert("a", FieldValue::uint(1));
        map.insert("b", FieldValue::uint(2));
        map.insert("c", FieldValue::uint(3));

        assert_eq!(FieldLookup::get(&map, "a"), Some(&FieldValue::uint(1)));
        assert_eq!(FieldLookup::get(&map, "c"), Some(&FieldValue::uint(3)));
        assert_eq!(FieldLookup::get(&map, "missing"), None);
    }

    #[test]
    fn field_lookup_works_for_both_string_and_text_keyed_hash_maps() {
        let mut by_string: HashMap<String, FieldValue> = HashMap::new();
        by_string.insert("x".to_string(), FieldValue::uint(9));
        assert_eq!(
            FieldLookup::get(&by_string, "x"),
            Some(&FieldValue::uint(9))
        );

        let mut by_text: HashMap<Text, FieldValue> = HashMap::new();
        by_text.insert(Text::from("x"), FieldValue::uint(9));
        assert_eq!(FieldLookup::get(&by_text, "x"), Some(&FieldValue::uint(9)));
    }
}
