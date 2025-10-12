pub mod common_parsers;
pub mod err;
pub mod registry;
pub mod result;
pub mod transport;
pub mod transport_parsers;
pub mod transport_registry;

//#[cfg(test)]
//mod test;

use crate::event::RawEvent;
use crate::ingest::parser::result::ParseResult;

// Re-export transport types for convenience
pub use transport::{TransportParser, TransportParserFn};
pub use transport_registry::TransportRegistry;

/// Type alias for parser function - takes ownership of RawEvent
pub type ParserFn = fn(RawEvent) -> ParseResult;

/// High-performance parser struct - no trait overhead
#[derive(Clone)]
pub struct LogParser {
    /// Unique identifier for this parser
    pub id: &'static str,

    /// Human-readable name for this parser
    pub name: &'static str,

    /// Description of what this parser handles
    pub description: &'static str,

    /// The actual parsing function
    pub parse_fn: ParserFn,
}

impl LogParser {
    /// Create a new parser with the given function
    pub fn new(
        id: &'static str,
        name: &'static str,
        description: &'static str,
        parse_fn: ParserFn,
    ) -> Self {
        Self {
            id,
            name,
            description,
            parse_fn,
        }
    }

    /// Parse a log using this parser's function
    /// Creates a RawEvent from the log text and passes it to the parser
    pub fn parse(&self, log_text: &str, source: &str) -> ParseResult {
        let raw_event = RawEvent::from_log(log_text, source);
        (self.parse_fn)(raw_event)
    }
}
