//! Log intake: turning raw log data into events.
//!
//! Acquiring the data (sockets, file tailing, queues, agents) is the
//! application's: inputs differ too much in cursors, backpressure and
//! progress reporting for one shared trait to help.
//!
//! - [`framing`] splits TCP/TLS syslog byte streams into messages
//!   (RFC 6587), without doing any I/O itself.
//! - [`parser`] turns raw log text into structured events: [`parser::LogParser`]
//!   for content parsing and [`parser::transport`] for transport-layer parsing.

pub mod framing;
pub mod parser;
