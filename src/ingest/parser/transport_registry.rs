use super::priorities::{Order, Priorities};
use crate::event::Origin;
use crate::ingest::parser::transport::{TransportParser, TransportResult};
use std::collections::HashMap;

/// Configuration for the transport registry
#[derive(Debug, Clone)]
pub struct TransportRegistryConfig {
    /// Remember, per source, which transport parser matched, and try it
    /// first next time.
    pub enable_adaptive_learning: bool,
    /// How many learned parsers to remember per source.
    pub max_parsers_per_source: usize,
}

impl Default for TransportRegistryConfig {
    fn default() -> Self {
        Self {
            enable_adaptive_learning: true,
            max_parsers_per_source: 5,
        }
    }
}

impl TransportRegistryConfig {
    /// No learning: every message tries the configured patterns, then every
    /// parser, in order.
    pub fn without_learning() -> Self {
        Self {
            enable_adaptive_learning: false,
            ..Self::default()
        }
    }
}

/// Registry for transport parsers (syslog, file, network framing) with
/// adaptive learning.
///
/// [`TransportRegistry::parse`] returns the matching parser's
/// [`TransportResult`] unchanged: on success its [`crate::event::RawEvent`]
/// carries the transport fields and the isolated body, ready for a
/// [`super::registry::ParserRegistry`]. It takes `&self`, so one registry
/// can be shared by every worker thread.
#[derive(Default)]
pub struct TransportRegistry {
    parsers: Vec<TransportParser>,
    /// Learned (or configured) per-source order.
    priorities: Priorities,
    /// Preferred order per origin kind (`"network"`, `"file"`, ...).
    origin_patterns: HashMap<&'static str, Order>,
    config: TransportRegistryConfig,
}

impl TransportRegistry {
    /// Create a new transport registry with default config
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new transport registry with custom config
    pub fn with_config(config: TransportRegistryConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Update registry configuration
    pub fn set_config(&mut self, config: TransportRegistryConfig) {
        self.config = config;
    }

    /// Get current registry configuration
    pub fn config(&self) -> &TransportRegistryConfig {
        &self.config
    }

    /// A [`crate::capability::ComponentManifest`] for every registered
    /// transport parser — see [`crate::ingest::parser::registry::ParserRegistry::manifests`].
    pub fn manifests(&self) -> Vec<crate::capability::ComponentManifest> {
        self.parsers
            .iter()
            .map(|parser| {
                crate::capability::ComponentManifest::new(
                    format!("transport_parser/{}", parser.id),
                    crate::capability::ComponentKind::TransportParser,
                    parser.name,
                    parser.description,
                )
            })
            .collect()
    }

    /// Register a new transport parser.
    ///
    /// # Panics
    ///
    /// Beyond 65 535 parsers.
    pub fn register(&mut self, parser: TransportParser) {
        assert!(self.parsers.len() < u16::MAX as usize, "too many parsers");
        self.parsers.push(parser);
    }

    /// Configure the preferred parser order for a kind of origin
    /// (`"network"`, `"hostname"`, `"collector"`, `"file"`, `"container"`).
    /// Example: `configure_origin_pattern("network", vec![syslog_idx, tcp_idx])`
    pub fn configure_origin_pattern(
        &mut self,
        origin_type: &'static str,
        parser_indices: Vec<usize>,
    ) {
        let order = parser_indices
            .into_iter()
            .filter_map(|i| u16::try_from(i).ok())
            .collect();
        self.origin_patterns.insert(origin_type, order);
    }

    /// Parse a message: first with the parsers learned for this source,
    /// then the origin kind's configured pattern, then every other parser.
    /// Returns the first parser's result that is not `NoMatch`, or
    /// `NoMatch(source)` when none matched.
    pub fn parse(&self, log_text: &str, source: Origin) -> TransportResult {
        let learned = self.priorities.get(&source);
        let pattern = self
            .origin_patterns
            .get(origin_type(&source))
            .map(|o| o.as_slice())
            .unwrap_or(&[]);

        let mut tried: Order = Order::new();
        for &idx in learned.iter().chain(pattern) {
            if tried.contains(&idx) {
                continue;
            }
            tried.push(idx);
            let Some(parser) = self.parsers.get(idx as usize) else {
                continue;
            };
            match parser.parse(log_text, source.clone()) {
                TransportResult::NoMatch(_) => continue,
                matched => {
                    if !learned.contains(&idx) {
                        self.learn(&source, idx);
                    }
                    return matched;
                }
            }
        }

        for (idx, parser) in self.parsers.iter().enumerate() {
            let idx = idx as u16;
            if tried.contains(&idx) {
                continue;
            }
            match parser.parse(log_text, source.clone()) {
                TransportResult::NoMatch(_) => continue,
                matched => {
                    self.learn(&source, idx);
                    return matched;
                }
            }
        }
        TransportResult::NoMatch(source)
    }

    fn learn(&self, source: &Origin, idx: u16) {
        if self.config.enable_adaptive_learning {
            self.priorities
                .learn(source, idx, self.config.max_parsers_per_source);
        }
    }

    /// Get parser information for debugging
    pub fn get_parser_info(&self) -> Vec<(&str, &str)> {
        self.parsers.iter().map(|p| (p.id, p.name)).collect()
    }

    /// The learned order per source, for diagnostics.
    pub fn source_priorities(&self) -> HashMap<Origin, Vec<usize>> {
        self.priorities.snapshot()
    }
}

/// The origin kind used by [`TransportRegistry::configure_origin_pattern`].
fn origin_type(source: &Origin) -> &'static str {
    match source {
        Origin::Ip(_) => "network",
        Origin::Hostname(_) => "hostname",
        Origin::Collector(_) => "collector",
        Origin::File(_) => "file",
        Origin::Container { .. } => "container",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::RawEvent;
    use crate::event::field::Timestamp;

    fn prefix_parser(prefix: &'static str) -> TransportParser {
        TransportParser::new(
            prefix,
            prefix,
            "test",
            move |text: &str, origin: Origin| match text.strip_prefix(prefix) {
                Some(body) => TransportResult::Success(RawEvent::new(
                    body.to_string(),
                    Timestamp::now(),
                    origin,
                )),
                None => TransportResult::NoMatch(origin),
            },
        )
    }

    #[test]
    fn returns_the_raw_event_for_content_parsing() {
        let mut registry = TransportRegistry::new();
        registry.register(prefix_parser("<13>"));
        match registry.parse("<13>hello", Origin::from_hostname("h")) {
            TransportResult::Success(raw) => assert_eq!(raw.log_text, "hello"),
            other => panic!("expected Success, got {other:?}"),
        }
        assert!(matches!(
            registry.parse("plain", Origin::from_hostname("h")),
            TransportResult::NoMatch(_)
        ));
    }

    #[test]
    fn errors_and_discards_are_not_turned_into_success() {
        let mut registry = TransportRegistry::new();
        registry.register(TransportParser::new(
            "err",
            "err",
            "test",
            |text: &str, origin| {
                TransportResult::Error(RawEvent::new(text.to_string(), Timestamp::now(), origin))
            },
        ));
        assert!(matches!(
            registry.parse("x", Origin::from_hostname("h")),
            TransportResult::Error(_)
        ));
    }

    #[test]
    fn origin_pattern_and_learning() {
        let mut registry = TransportRegistry::new();
        registry.register(prefix_parser("A"));
        registry.register(prefix_parser("B"));
        registry.configure_origin_pattern("hostname", vec![1]);
        assert!(matches!(
            registry.parse("Bx", Origin::from_hostname("h")),
            TransportResult::Success(_)
        ));
        assert_eq!(
            registry
                .source_priorities()
                .get(&Origin::from_hostname("h")),
            Some(&vec![1])
        );
        // Falls back past the pattern.
        assert!(matches!(
            registry.parse("Ax", Origin::from_hostname("h")),
            TransportResult::Success(_)
        ));
    }
}
