use super::priorities::{Order, Priorities};
use super::{LogParser, result::ParseResult};
use crate::event::{Origin, RawEvent};
use std::collections::HashMap;

/// Configuration for the parser registry
#[derive(Debug, Clone)]
pub struct ParserRegistryConfig {
    /// Remember, per source, which parser matched, and try it first next
    /// time.
    pub enable_adaptive_learning: bool,
    /// How many learned parsers to remember per source.
    pub max_parsers_per_source: usize,
}

impl Default for ParserRegistryConfig {
    fn default() -> Self {
        Self {
            enable_adaptive_learning: true,
            max_parsers_per_source: 5,
        }
    }
}

/// Parser registry for managing multiple parsers.
///
/// [`ParserRegistry::parse`] takes `&self`: one registry can be shared by
/// every worker thread (e.g. in an `Arc`). Learned priorities sit behind a
/// read-mostly lock that parsing never holds.
#[derive(Default)]
pub struct ParserRegistry {
    parsers: Vec<LogParser>,
    priorities: Priorities,
    config: ParserRegistryConfig,
}

impl ParserRegistry {
    /// Create a new empty parser registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new parser registry with custom config
    pub fn with_config(config: ParserRegistryConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Update registry configuration
    pub fn set_config(&mut self, config: ParserRegistryConfig) {
        self.config = config;
    }

    /// Get current registry configuration
    pub fn config(&self) -> &ParserRegistryConfig {
        &self.config
    }

    /// Register a new parser.
    ///
    /// # Panics
    ///
    /// Beyond 65 535 parsers.
    pub fn register(&mut self, parser: LogParser) {
        assert!(self.parsers.len() < u16::MAX as usize, "too many parsers");
        self.parsers.push(parser);
    }

    /// Fixes the order in which parsers are tried for `origin` (indices in
    /// registration order). Unknown indices are skipped when parsing.
    pub fn set_source_priority(&self, origin: &Origin, parser_indices: Vec<usize>) {
        let order: Order = parser_indices
            .into_iter()
            .filter_map(|i| u16::try_from(i).ok())
            .collect();
        self.priorities.set(origin.clone(), order);
    }

    /// The learned or configured order per source, for diagnostics.
    pub fn source_priorities(&self) -> HashMap<Origin, Vec<usize>> {
        self.priorities.snapshot()
    }

    /// Parse a log: first with the parsers that matched this source before,
    /// then with every other parser, in registration order. A parser that
    /// matches (success, error or discard) is remembered for the source when
    /// adaptive learning is on.
    pub fn parse(&self, mut raw_event: RawEvent) -> ParseResult {
        let tried = self.priorities.get(&raw_event.source);
        for &idx in &tried {
            let Some(parser) = self.parsers.get(idx as usize) else {
                continue;
            };
            match parser.call(raw_event) {
                ParseResult::NoMatch(returned) => raw_event = returned,
                matched => return matched,
            }
        }

        // Kept for learning: the RawEvent is moved into each parser.
        let source = self
            .config
            .enable_adaptive_learning
            .then(|| raw_event.source.clone());
        for (idx, parser) in self.parsers.iter().enumerate() {
            let idx = idx as u16;
            if tried.contains(&idx) {
                continue;
            }
            match parser.call(raw_event) {
                ParseResult::NoMatch(returned) => raw_event = returned,
                matched => {
                    if let Some(source) = &source {
                        self.priorities
                            .learn(source, idx, self.config.max_parsers_per_source);
                    }
                    return matched;
                }
            }
        }

        // No parser matched - return the original RawEvent. Common for free-text
        // syslog, so debug rather than warn.
        crate::log_debug!(
            "parser_registry",
            "no registered parser matched a log from {:?}",
            raw_event.source
        );
        ParseResult::NoMatch(raw_event)
    }

    /// Get all registered parsers
    pub fn parsers(&self) -> &[LogParser] {
        &self.parsers
    }

    /// Get parser by ID
    pub fn get_parser(&self, id: &str) -> Option<&LogParser> {
        self.parsers.iter().find(|p| p.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::Timestamp;

    fn raw(text: &str, host: &str) -> RawEvent {
        RawEvent::new(
            text.to_string(),
            Timestamp::now(),
            Origin::from_hostname(host),
        )
    }

    fn matches_prefix(prefix: &'static str) -> LogParser {
        LogParser::new(prefix, prefix, "test", move |raw: RawEvent| {
            if raw.log_text.starts_with(prefix) {
                ParseResult::Success(raw.into_event())
            } else {
                ParseResult::NoMatch(raw)
            }
        })
    }

    #[test]
    fn learns_the_matching_parser_per_source() {
        let mut registry = ParserRegistry::new();
        registry.register(matches_prefix("a"));
        registry.register(matches_prefix("b"));

        assert!(matches!(
            registry.parse(raw("b1", "h")),
            ParseResult::Success(_)
        ));
        let learned = registry.source_priorities();
        assert_eq!(learned.get(&Origin::from_hostname("h")), Some(&vec![1]));

        // Still falls back for a log the learned parser doesn't match.
        assert!(matches!(
            registry.parse(raw("a1", "h")),
            ParseResult::Success(_)
        ));
        assert!(matches!(
            registry.parse(raw("zz", "h")),
            ParseResult::NoMatch(_)
        ));
    }

    #[test]
    fn learning_can_be_disabled() {
        let mut registry = ParserRegistry::with_config(ParserRegistryConfig {
            enable_adaptive_learning: false,
            ..ParserRegistryConfig::default()
        });
        registry.register(matches_prefix("a"));
        assert!(matches!(
            registry.parse(raw("a1", "h")),
            ParseResult::Success(_)
        ));
        assert!(registry.source_priorities().is_empty());
    }

    #[test]
    fn registry_is_shareable_across_threads() {
        let mut registry = ParserRegistry::new();
        registry.register(matches_prefix("a"));
        let registry = std::sync::Arc::new(registry);
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let registry = registry.clone();
                std::thread::spawn(move || {
                    for i in 0..100 {
                        let host = format!("h{}", (t * 100 + i) % 7);
                        assert!(matches!(
                            registry.parse(raw("a", &host)),
                            ParseResult::Success(_)
                        ));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(registry.source_priorities().len(), 7);
    }
}
