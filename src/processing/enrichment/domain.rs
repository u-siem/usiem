//! A domain-name table with suffix matching: [`DomainSet`].
//!
//! For domain blocklists and allowlists: an entry `evil.example` matches
//! `evil.example` itself and every name below it (`a.b.evil.example`), but
//! not `notevil.example`. Matching walks the name's label suffixes, longest
//! first, so a lookup is at most one hash probe per label.

use std::collections::HashMap;

/// Immutable domain → value table, matching a name or any of its parents.
///
/// Built once; updates build a new table (wrap it in an `Arc` and swap
/// it). Names are compared lowercase, without a trailing dot. When the
/// same domain appears twice, the later value wins.
///
/// ```
/// use usiem::processing::enrichment::DomainSet;
///
/// let set = DomainSet::from_pairs([("evil.example", "malware"), ("ads.example.net", "ads")]);
/// assert_eq!(set.get("cdn.EVIL.example."), Some(("evil.example", &"malware")));
/// assert_eq!(set.get("notevil.example"), None);
/// ```
#[derive(Debug, Clone)]
pub struct DomainSet<V> {
    entries: HashMap<Box<str>, V>,
}

impl<V> Default for DomainSet<V> {
    fn default() -> Self {
        DomainSet {
            entries: HashMap::new(),
        }
    }
}

/// Lowercase, without surrounding whitespace or a trailing dot; `None`
/// when nothing is left or the name has an empty label.
pub fn normalize_domain(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.split('.').any(str::is_empty) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

impl<V> DomainSet<V> {
    /// Builds the table; entries that are not valid names are skipped.
    pub fn from_pairs<S: AsRef<str>>(pairs: impl IntoIterator<Item = (S, V)>) -> Self {
        let mut entries = HashMap::new();
        for (name, value) in pairs {
            if let Some(name) = normalize_domain(name.as_ref()) {
                entries.insert(name.into_boxed_str(), value);
            }
        }
        DomainSet { entries }
    }

    /// The longest listed suffix of `name` (the name itself first, then
    /// its parents), with its value.
    pub fn get(&self, name: &str) -> Option<(&str, &V)> {
        if self.entries.is_empty() {
            return None;
        }
        let name = name.trim().trim_end_matches('.');
        // Avoid allocating when the name is already lowercase.
        let lowered;
        let name = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = name.to_ascii_lowercase();
            lowered.as_str()
        } else {
            name
        };
        let mut rest = name;
        loop {
            if let Some((key, value)) = self.entries.get_key_value(rest) {
                return Some((key, value));
            }
            let dot = rest.find('.')?;
            rest = &rest[dot + 1..];
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.entries.iter().map(|(k, v)| (&**k, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_parent_matches() {
        let set = DomainSet::from_pairs([("evil.example", 1), ("deep.ok.example", 2)]);
        assert_eq!(set.get("evil.example"), Some(("evil.example", &1)));
        assert_eq!(set.get("a.b.evil.example"), Some(("evil.example", &1)));
        assert_eq!(set.get("x.deep.ok.example"), Some(("deep.ok.example", &2)));
        assert_eq!(set.get("ok.example"), None);
        assert_eq!(set.get("example"), None);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn labels_not_substrings() {
        let set = DomainSet::from_pairs([("evil.example", ())]);
        assert!(!set.contains("notevil.example"));
        assert!(!set.contains("evil.example.com"));
        assert!(!set.contains("evilexample"));
    }

    #[test]
    fn longest_suffix_wins() {
        let set = DomainSet::from_pairs([("example", "tld"), ("bad.example", "bad")]);
        assert_eq!(set.get("x.bad.example"), Some(("bad.example", &"bad")));
        assert_eq!(set.get("good.example"), Some(("example", &"tld")));
    }

    #[test]
    fn normalization() {
        let set = DomainSet::from_pairs([(" Evil.Example. ", 1), ("", 2), ("a..b", 3), (".", 4)]);
        assert_eq!(set.len(), 1);
        assert!(set.contains("WWW.EVIL.EXAMPLE."));
        assert!(set.contains("xn--bcher-kva.evil.example"));
        assert_eq!(normalize_domain("a..b"), None);
        assert_eq!(normalize_domain("Host.Lan."), Some("host.lan".into()));
    }

    #[test]
    fn later_value_wins_and_empty_set() {
        let set = DomainSet::from_pairs([("a.example", 1), ("A.example", 2)]);
        assert_eq!(set.get("a.example"), Some(("a.example", &2)));
        let empty: DomainSet<()> = DomainSet::default();
        assert!(empty.get("anything").is_none());
        assert!(empty.is_empty());
    }
}
