use crate::event::{Origin, RawEvent};
use crate::ingest::parser::result::ParseResult;
use crate::ingest::parser::transport::{TransportParser, TransportResult};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Configuration for the transport registry
#[derive(Debug, Clone)]
pub struct TransportRegistryConfig {
    /// Enable performance metadata tracking
    pub enable_metadata: bool,
    /// Maximum number of parsers to track per source
    pub max_parsers_per_source: usize,
    /// Enable adaptive parser learning
    pub enable_adaptive_learning: bool,
}

impl Default for TransportRegistryConfig {
    fn default() -> Self {
        Self {
            enable_metadata: true,
            max_parsers_per_source: 10,
            enable_adaptive_learning: true,
        }
    }
}

impl TransportRegistryConfig {
    /// Create config with metadata disabled for performance
    pub fn no_metadata() -> Self {
        Self {
            enable_metadata: false,
            max_parsers_per_source: 10,
            enable_adaptive_learning: true,
        }
    }

    /// Create config optimized for performance (minimal tracking)
    pub fn performance_optimized() -> Self {
        Self {
            enable_metadata: false,
            max_parsers_per_source: 3,
            enable_adaptive_learning: false,
        }
    }
}

/// Registry for transport parsers with adaptive learning
/// Transport parsers handle protocol-level parsing (syslog, file, network streams)
pub struct TransportRegistry {
    /// Registered transport parsers
    parsers: Vec<TransportParser>,

    /// Source-specific parser priorities for exact origin matching
    /// Maps origin hash to ordered parser indices
    source_priorities: HashMap<u64, Vec<usize>>,

    /// Origin type patterns for automatic parser selection  
    /// Maps origin types to preferred parser orders
    origin_patterns: HashMap<&'static str, Vec<usize>>,

    /// Registry configuration
    config: TransportRegistryConfig,
}

impl TransportRegistry {
    /// Create a new transport registry with default config
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
            source_priorities: HashMap::new(),
            origin_patterns: HashMap::new(),
            config: TransportRegistryConfig::default(),
        }
    }

    /// Create a new transport registry with custom config
    pub fn with_config(config: TransportRegistryConfig) -> Self {
        Self {
            parsers: Vec::new(),
            source_priorities: HashMap::new(),
            origin_patterns: HashMap::new(),
            config,
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

    /// Hash an Origin to get a u64 key for exact matching
    fn hash_origin(origin: &Origin) -> u64 {
        let mut hasher = DefaultHasher::new();
        origin.hash(&mut hasher);
        hasher.finish()
    }

    /// Register a new transport parser
    pub fn register(&mut self, parser: TransportParser) {
        self.parsers.push(parser);
    }

    /// Parse a log message using registered transport parsers
    /// Returns RawEvent with transport metadata populated and body isolated for content parsing
    pub fn parse(&mut self, log_text: &str, source: Origin) -> ParseResult {
        let origin_hash = Self::hash_origin(&source);

        // Try parsers in source-specific priority order first
        if let Some(indices) = self.source_priorities.get(&origin_hash).cloned() {
            for (priority_pos, &idx) in indices.iter().enumerate() {
                if let Some(parser) = self.parsers.get(idx) {
                    match parser.parse(log_text, source.clone()) {
                        TransportResult::Success(raw_event) => {
                            // Success: Move this parser to front of priority list
                            self.promote_parser_for_source(origin_hash, idx, priority_pos);
                            return ParseResult::Success(raw_event.into_event());
                        }
                        TransportResult::Error(raw_event) => {
                            // Transport error: Still a match, promote parser and pass through for content parsing
                            self.promote_parser_for_source(origin_hash, idx, priority_pos);
                            return ParseResult::Success(raw_event.into_event());
                        }
                        TransportResult::Discard(raw_event) => {
                            // Transport discard: Still a match, promote parser and pass through for content parsing
                            self.promote_parser_for_source(origin_hash, idx, priority_pos);
                            return ParseResult::Success(raw_event.into_event());
                        }
                        TransportResult::NoMatch(_) => continue,
                    }
                }
            }
        }

        // Try origin-pattern based parsers
        let origin_type = self.get_origin_type(&source);
        if let Some(indices) = self.origin_patterns.get(origin_type).cloned() {
            for &idx in &indices {
                if let Some(parser) = self.parsers.get(idx) {
                    // Skip if already tried in source priorities
                    if self
                        .source_priorities
                        .get(&origin_hash)
                        .is_some_and(|prios| prios.contains(&idx))
                    {
                        continue;
                    }

                    match parser.parse(log_text, source.clone()) {
                        TransportResult::Success(raw_event) => {
                            self.add_parser_to_source_priority(origin_hash, idx);
                            return ParseResult::Success(raw_event.into_event());
                        }
                        TransportResult::Error(raw_event) => {
                            self.add_parser_to_source_priority(origin_hash, idx);
                            return ParseResult::Success(raw_event.into_event());
                        }
                        TransportResult::Discard(raw_event) => {
                            self.add_parser_to_source_priority(origin_hash, idx);
                            return ParseResult::Success(raw_event.into_event());
                        }
                        TransportResult::NoMatch(_) => continue,
                    }
                }
            }
        }

        // Fallback: try all remaining parsers
        for (idx, parser) in self.parsers.iter().enumerate() {
            // Skip if already tried
            let already_tried = self
                .source_priorities
                .get(&origin_hash)
                .is_some_and(|prios| prios.contains(&idx))
                || self
                    .origin_patterns
                    .get(origin_type)
                    .is_some_and(|prios| prios.contains(&idx));

            if already_tried {
                continue;
            }

            match parser.parse(log_text, source.clone()) {
                TransportResult::Success(raw_event) => {
                    self.add_parser_to_source_priority(origin_hash, idx);
                    return ParseResult::Success(raw_event.into_event());
                }
                TransportResult::Error(raw_event) => {
                    self.add_parser_to_source_priority(origin_hash, idx);
                    return ParseResult::Success(raw_event.into_event());
                }
                TransportResult::Discard(raw_event) => {
                    self.add_parser_to_source_priority(origin_hash, idx);
                    return ParseResult::Success(raw_event.into_event());
                }
                TransportResult::NoMatch(_) => continue,
            }
        }

        // No transport parser matched - create a RawEvent with the original data
        // This represents a "raw" transport where the entire message is the body
        let raw_event = RawEvent::new(
            log_text.to_string(),
            crate::event::field::Timestamp::now(),
            source,
        );
        ParseResult::NoMatch(raw_event)
    }

    /// Check if metadata tracking is enabled
    pub fn is_metadata_enabled(&self) -> bool {
        self.config.enable_metadata
    }

    /// Configure origin-based parser patterns for automatic selection  
    /// Example: configure_origin_pattern("network", vec![syslog_idx, tcp_idx])
    pub fn configure_origin_pattern(
        &mut self,
        origin_type: &'static str,
        parser_indices: Vec<usize>,
    ) {
        self.origin_patterns.insert(origin_type, parser_indices);
    }

    /// Get origin type for pattern matching
    fn get_origin_type(&self, source: &Origin) -> &'static str {
        match source {
            Origin::Ip(_) => "network",
            Origin::Hostname(_) => "hostname",
            Origin::Collector(_) => "collector",
            Origin::File(_) => "file",
            Origin::Container { .. } => "container",
        }
    }

    /// Move a successful parser to the front of the priority list for a source
    fn promote_parser_for_source(
        &mut self,
        origin_hash: u64,
        _parser_idx: usize,
        current_pos: usize,
    ) {
        if let Some(priorities) = self.source_priorities.get_mut(&origin_hash)
            && current_pos > 0
            && priorities.len() > current_pos
        {
            // Move parser to front
            let parser = priorities.remove(current_pos);
            priorities.insert(0, parser);
        }
    }

    /// Add a parser to the source priority list
    fn add_parser_to_source_priority(&mut self, origin_hash: u64, parser_idx: usize) {
        self.source_priorities
            .entry(origin_hash)
            .or_default()
            .insert(0, parser_idx);
    }

    /// Get parser information for debugging
    pub fn get_parser_info(&self) -> Vec<(&str, &str)> {
        self.parsers.iter().map(|p| (p.id, p.name)).collect()
    }

    /// Get source priority information for debugging
    pub fn get_source_priorities(&self) -> &HashMap<u64, Vec<usize>> {
        &self.source_priorities
    }
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}
