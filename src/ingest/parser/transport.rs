use crate::event::{Origin, RawEvent};

/// Result of transport parser operations
/// Different from ParseResult as transport parsers work with strings and Origins, not RawEvents
#[derive(Debug)]
pub enum TransportResult {
    /// Successfully parsed transport - contains RawEvent ready for content parsing
    Success(RawEvent),
    /// Parsing failed with error - contains RawEvent with error context
    Error(RawEvent),
    /// Should discard this log - contains RawEvent with discard reason
    Discard(RawEvent),
    /// Transport parser didn't match - return original Origin for next parser
    NoMatch(Origin),
}

/// Function signature for transport parsers
/// Transport parsers extract metadata from transport protocols (syslog, file, network)
/// and return a RawEvent with transport metadata populated and body ready for content parsing
pub type TransportParserFn = fn(&str, Origin) -> TransportResult;

/// Transport parser that handles protocol-specific parsing
/// Extracts transport metadata and isolates content body for further parsing
#[derive(Debug, Clone)]
pub struct TransportParser {
    /// Unique identifier for this transport parser
    pub id: &'static str,

    /// Human-readable name
    pub name: &'static str,

    /// Description of what this transport parser does
    pub description: &'static str,

    /// The parsing function
    pub parse_fn: TransportParserFn,
}

impl TransportParser {
    /// Create a new transport parser
    pub fn new(
        id: &'static str,
        name: &'static str,
        description: &'static str,
        parse_fn: TransportParserFn,
    ) -> Self {
        Self {
            id,
            name,
            description,
            parse_fn,
        }
    }

    /// Parse a raw log message with this transport parser
    pub fn parse(&self, log_text: &str, source: Origin) -> TransportResult {
        (self.parse_fn)(log_text, source)
    }
}
