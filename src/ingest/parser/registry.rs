use super::{LogParser, result::ParseResult};
use crate::event::{Origin, RawEvent};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Configuration for the parser registry
#[derive(Debug, Clone)]
pub struct ParserRegistryConfig {
    /// Enable performance metadata tracking
    pub enable_metadata: bool,
    /// Maximum number of parsers to track per source
    pub max_parsers_per_source: usize,
    /// Enable adaptive parser learning
    pub enable_adaptive_learning: bool,
}

impl Default for ParserRegistryConfig {
    fn default() -> Self {
        Self {
            enable_metadata: true,
            max_parsers_per_source: 10,
            enable_adaptive_learning: true,
        }
    }
}

/// Parser registry for managing multiple parsers
#[derive(Default)]
pub struct ParserRegistry {
    parsers: Vec<LogParser>,
    // Priority mapping by source origin hash for exact matching
    source_priorities: HashMap<u64, Vec<usize>>,
    // Registry configuration
    config: ParserRegistryConfig,
}

impl ParserRegistry {
    /// Create a new empty parser registry
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
            source_priorities: HashMap::new(),
            config: ParserRegistryConfig::default(),
        }
    }

    /// Create a new parser registry with custom config
    pub fn with_config(config: ParserRegistryConfig) -> Self {
        Self {
            parsers: Vec::new(),
            source_priorities: HashMap::new(),
            config,
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

    /// A [`crate::capability::ComponentManifest`] for every registered
    /// parser, derived from the `id`/`name`/`description` it already
    /// carries — parsers stay plain `fn` pointers (no [`crate::capability::Component`]
    /// impl), so this is how they participate in the capability catalog. See
    /// `crate::capability` module docs.
    pub fn manifests(&self) -> Vec<crate::capability::ComponentManifest> {
        self.parsers
            .iter()
            .map(|parser| {
                crate::capability::ComponentManifest::new(
                    format!("parser/{}", parser.id),
                    crate::capability::ComponentKind::Parser,
                    parser.name,
                    parser.description,
                )
            })
            .collect()
    }

    /// Hash an Origin to get a u64 key for exact matching
    fn hash_origin(origin: &Origin) -> u64 {
        let mut hasher = DefaultHasher::new();
        origin.hash(&mut hasher);
        hasher.finish()
    }

    /// Register a new parser
    pub fn register(&mut self, parser: LogParser) {
        self.parsers.push(parser);
    }

    /// Set parser priority order for a specific source origin
    pub fn set_source_priority(&mut self, origin: &Origin, parser_indices: Vec<usize>) {
        let origin_hash = Self::hash_origin(origin);
        self.source_priorities.insert(origin_hash, parser_indices);
    }

    /// Parse a log using parsers in priority order for the source
    /// Automatically learns and updates source priorities based on successful matches
    /// Uses zero-allocation pattern: creates RawEvent once, passes through parsers
    pub fn parse(&mut self, mut raw_event: RawEvent) -> ParseResult {
        // Try parsers in source-specific priority order first
        let origin_hash = Self::hash_origin(&raw_event.source);
        if let Some(indices) = self.source_priorities.get(&origin_hash).cloned() {
            for &idx in indices.iter() {
                if let Some(parser) = self.parsers.get(idx) {
                    match (parser.parse_fn)(raw_event) {
                        result @ ParseResult::Success(_) => {
                            return result;
                        }
                        result @ ParseResult::Error(_) => {
                            return result;
                        }
                        result @ ParseResult::Discard(_) => {
                            return result;
                        }
                        ParseResult::NoMatch(returned_event) => {
                            // Parser didn't match, get the RawEvent back and try next parser
                            raw_event = returned_event;
                            continue;
                        }
                    }
                }
            }
        }
        // Fallback to trying all parsers not in priority list
        let source_origin = raw_event.source.clone(); // Store origin for later use
        for (idx, parser) in self.parsers.iter().enumerate() {
            match (parser.parse_fn)(raw_event) {
                result @ ParseResult::Success(_) => {
                    // Success: Add this parser to source priority list
                    self.add_parser_to_source_priority(&source_origin, idx);
                    return result;
                }
                result @ ParseResult::Error(_) => {
                    // Error: Still a match, add parser to source priority
                    self.add_parser_to_source_priority(&source_origin, idx);
                    return result;
                }
                result @ ParseResult::Discard(_) => {
                    // Discard: Still a match, add parser to source priority
                    self.add_parser_to_source_priority(&source_origin, idx);
                    return result;
                }
                ParseResult::NoMatch(returned_event) => {
                    // Parser didn't match, get the RawEvent back and try next parser
                    raw_event = returned_event;
                    continue;
                }
            }
        }

        // No parser matched - return the original RawEvent
        crate::log_warn!(
            "parser_registry",
            "no registered parser matched a log from {:?}",
            raw_event.source
        );
        ParseResult::NoMatch(raw_event)
    }

    /// Check if metadata tracking is enabled
    pub fn is_metadata_enabled(&self) -> bool {
        self.config.enable_metadata
    }

    /// Get all registered parsers
    pub fn parsers(&self) -> &[LogParser] {
        &self.parsers
    }

    /// Get parser by ID
    pub fn get_parser(&self, id: &str) -> Option<&LogParser> {
        self.parsers.iter().find(|p| p.id == id)
    }

    /// Add a parser to source priority list (as highest priority)
    fn add_parser_to_source_priority(&mut self, origin: &Origin, parser_idx: usize) {
        // Get or create priority list for this origin
        let origin_hash = Self::hash_origin(origin);
        let indices = self.source_priorities.entry(origin_hash).or_default();

        // Add to front if not already present
        if !indices.contains(&parser_idx) {
            indices.insert(0, parser_idx);

            // Limit the priority list size to prevent unbounded growth
            const MAX_PRIORITY_PARSERS: usize = 5;
            if indices.len() > MAX_PRIORITY_PARSERS {
                indices.truncate(MAX_PRIORITY_PARSERS);
            }
        }
    }
}
