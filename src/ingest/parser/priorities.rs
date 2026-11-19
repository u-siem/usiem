//! Learned "which parser matches this source" order, shared by
//! [`super::registry::ParserRegistry`] and
//! [`super::transport_registry::TransportRegistry`].
//!
//! Lookups take a read lock and copy out a small inline list, so parsing
//! never holds the lock and concurrent parsers on many threads only contend
//! when a source learns a new parser, which happens once per
//! (source, parser) pair.

use crate::event::Origin;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Parser indices in the order to try them.
pub(crate) type Order = SmallVec<[u16; 4]>;

/// Above this many distinct sources, new sources are no longer learned (one
/// per sending IP could otherwise grow without bound). Known sources keep
/// their order.
const MAX_SOURCES: usize = 16_384;

#[derive(Debug, Default)]
pub(crate) struct Priorities {
    by_source: RwLock<HashMap<Origin, Order>>,
}

impl Priorities {
    fn read(&self) -> RwLockReadGuard<'_, HashMap<Origin, Order>> {
        self.by_source.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<Origin, Order>> {
        self.by_source.write().unwrap_or_else(|e| e.into_inner())
    }

    /// The learned order for `origin` (empty when none).
    pub(crate) fn get(&self, origin: &Origin) -> Order {
        self.read().get(origin).cloned().unwrap_or_default()
    }

    /// Replaces the order for `origin`.
    pub(crate) fn set(&self, origin: Origin, order: Order) {
        self.write().insert(origin, order);
    }

    /// Moves `idx` to the front of `origin`'s order, keeping at most `max`
    /// entries. A no-op (read lock only) when it is already first.
    pub(crate) fn learn(&self, origin: &Origin, idx: u16, max: usize) {
        if self
            .read()
            .get(origin)
            .is_some_and(|o| o.first() == Some(&idx))
        {
            return;
        }
        let mut map = self.write();
        if !map.contains_key(origin) && map.len() >= MAX_SOURCES {
            return;
        }
        let order = map.entry(origin.clone()).or_default();
        order.retain(|i| *i != idx);
        order.insert(0, idx);
        order.truncate(max.max(1));
    }

    /// A copy of every learned order, for diagnostics.
    pub(crate) fn snapshot(&self) -> HashMap<Origin, Vec<usize>> {
        self.read()
            .iter()
            .map(|(o, order)| (o.clone(), order.iter().map(|i| *i as usize).collect()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learn_moves_to_front_and_bounds_length() {
        let p = Priorities::default();
        let o = Origin::from_hostname("h");
        p.learn(&o, 1, 2);
        p.learn(&o, 2, 2);
        assert_eq!(p.get(&o).as_slice(), &[2, 1]);
        p.learn(&o, 1, 2);
        assert_eq!(p.get(&o).as_slice(), &[1, 2]);
        p.learn(&o, 3, 2);
        assert_eq!(p.get(&o).as_slice(), &[3, 1]);
    }
}
