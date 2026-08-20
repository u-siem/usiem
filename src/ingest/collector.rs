//! Framework interface for log collection.
//!
//! This crate has no I/O or async runtime dependencies of its own — no TCP/UDP
//! listener, no file tailer, no message-queue consumer. External crates
//! implement [`Collector`] to own the actual networking, file-reading, or
//! async runtime choice, and hand the resulting [`RawEvent`]s to a
//! [`crate::ingest::parser::registry::ParserRegistry`].
//!
//! `Collector` is the ingest-side mirror of [`crate::processing::sink::Sink`]:
//! both are contracts only, with no concrete implementations shipped here.
//!
//! # Usage pattern
//!
//! ```rust,no_compile,no_run
//! // External library implements the interface, e.g. over a TCP listener
//! struct TcpSyslogCollector {
//!     listener: std::net::TcpListener,
//! }
//!
//! impl Collector for TcpSyslogCollector {
//!     fn collect(&mut self) -> Result<Option<RawEvent>, Box<dyn std::error::Error + Send + Sync>> {
//!         // Accept a connection, read a line, wrap it in a RawEvent...
//!         todo!()
//!     }
//! }
//!
//! // Application code drains the collector into a parser registry
//! let mut collector = TcpSyslogCollector { listener: /* ... */ };
//! while let Some(raw_event) = collector.collect()? {
//!     let result = registry.parse(raw_event);
//!     // ...
//! }
//! ```

use crate::event::RawEvent;

/// Framework interface for acquiring raw log data from an external source.
///
/// A `Collector` is a trait rather than an `fn` pointer (like
/// [`crate::processing::sink::Sink`], and unlike
/// [`crate::ingest::parser::LogParser`]) because real collectors need to hold
/// state — a socket, a file handle and read offset, a queue subscription.
pub trait Collector {
    /// Collect the next available raw event, if any.
    ///
    /// Returns `Ok(None)` when no event is currently available — this is not
    /// an error. Callers decide whether to poll again, block, or integrate
    /// this into their own I/O or async model; this trait makes no assumption
    /// about blocking vs. non-blocking behavior.
    fn collect(&mut self) -> Result<Option<RawEvent>, Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Origin;
    use std::collections::VecDeque;

    /// A trivial in-memory collector, useful for tests and as a minimal
    /// worked example of the trait.
    struct VecCollector {
        pending: VecDeque<String>,
        source: &'static str,
    }

    impl Collector for VecCollector {
        fn collect(
            &mut self,
        ) -> Result<Option<RawEvent>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self
                .pending
                .pop_front()
                .map(|line| RawEvent::from_log(&line, self.source)))
        }
    }

    #[test]
    fn test_collector_yields_events_then_none() {
        let mut collector = VecCollector {
            pending: VecDeque::from(["first line".to_string(), "second line".to_string()]),
            source: "test.log",
        };

        let first = collector.collect().unwrap().expect("expected an event");
        assert_eq!(first.log_text, "first line");
        assert_eq!(first.source, Origin::from_source_string("test.log"));

        let second = collector.collect().unwrap().expect("expected an event");
        assert_eq!(second.log_text, "second line");

        assert!(collector.collect().unwrap().is_none());
    }

    #[test]
    fn test_collector_is_usable_as_trait_object() {
        let mut collector: Box<dyn Collector> = Box::new(VecCollector {
            pending: VecDeque::from(["only line".to_string()]),
            source: "test.log",
        });

        let event = collector.collect().unwrap().expect("expected an event");
        assert_eq!(event.log_text, "only line");
    }
}
