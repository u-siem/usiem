//! Log intake: acquiring raw log data and turning it into events.
//!
//! - [`collector`] is the [`collector::Collector`] interface for acquiring
//!   raw log data from an external source (network, file, queue). This crate
//!   ships no concrete collectors — see that module's docs.
//! - [`framing`] splits TCP/TLS syslog byte streams into messages
//!   (RFC 6587), without doing any I/O itself.
//! - [`parser`] turns raw log text into structured events: [`parser::LogParser`]
//!   for content parsing and [`parser::transport`] for transport-layer parsing.

pub mod collector;
pub mod framing;
pub mod parser;
