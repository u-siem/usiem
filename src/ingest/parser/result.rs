use super::err::{DiscardReason, ParsingError};
use crate::event::{CoreEvent as Event, RawEvent};

#[derive(Debug)]
pub enum ParseResult {
    /// Successfully parsed the raw event into a structured event
    Success(Event),
    /// Failed to parse - return the original RawEvent for further processing
    NoMatch(RawEvent),
    /// Parse error with detailed categorization
    Error(ParsingError),
    /// Log should be discarded (spam, noise, etc.)
    Discard(DiscardReason),
}
