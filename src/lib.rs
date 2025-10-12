pub mod event;
pub mod ingest;
pub mod processing;

// Re-export commonly used types for easy access
pub mod prelude {
    // Core event types
    pub use crate::event::field::{FieldValue, Ip, Timestamp};
    pub use crate::event::{Event, Origin, RawEvent};

    // Parsing system
    pub use crate::ingest::parser::common_parsers::*;
    pub use crate::ingest::parser::registry::{ParserRegistry, ParserRegistryConfig};
    pub use crate::ingest::parser::result::ParseResult;
    pub use crate::ingest::parser::transport::{
        TransportParser, TransportParserFn, TransportResult,
    };
    pub use crate::ingest::parser::transport_parsers::*;
    pub use crate::ingest::parser::transport_registry::{
        TransportRegistry, TransportRegistryConfig,
    };
    pub use crate::ingest::parser::{LogParser, ParserFn};

    // Event schema
    pub use crate::event::Schema;
}
