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
use std::sync::Arc;

// Re-export transport types for convenience
pub use transport::{TransportParser, TransportParserFn};
pub use transport_registry::TransportRegistry;

/// A parser's function: takes ownership of the [`RawEvent`] and hands it
/// back inside [`ParseResult::NoMatch`] when the log isn't its format.
///
/// A shared closure, so a parser can carry configuration (a time zone, a
/// field mapping, a compiled rule set). A plain `fn` item works as well.
pub type ParserFn = Arc<dyn Fn(RawEvent) -> ParseResult + Send + Sync>;

/// A content parser: an identity plus the function that does the work.
/// Cheap to clone (the function is reference-counted).
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
        parse_fn: impl Fn(RawEvent) -> ParseResult + Send + Sync + 'static,
    ) -> Self {
        Self {
            id,
            name,
            description,
            parse_fn: Arc::new(parse_fn),
        }
    }

    /// Runs this parser over an already-built [`RawEvent`].
    pub fn call(&self, raw_event: RawEvent) -> ParseResult {
        (self.parse_fn)(raw_event)
    }

    /// Parse a log using this parser's function
    /// Creates a RawEvent from the log text and passes it to the parser
    pub fn parse(&self, log_text: &str, source: &str) -> ParseResult {
        self.call(RawEvent::from_log(log_text, source))
    }
}

impl std::fmt::Debug for LogParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogParser")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
