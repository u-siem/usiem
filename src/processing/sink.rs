//! Framework interface for event output destinations.
//!
//! Mirrors the design of [`crate::processing::enrichment::providers`]: this
//! module defines a contract only — no concrete implementations. This crate
//! has no I/O dependencies of its own (no HTTP client, no Kafka/database
//! driver), so shipping an [`Event`] to stdout, a file, Kafka, Elasticsearch,
//! or anywhere else is left to external crates that implement [`Sink`].
//!
//! # Usage pattern
//!
//! ```rust,no_compile,no_run
//! // External library implements the interface
//! struct StdoutSink;
//!
//! impl Sink for StdoutSink {
//!     fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!         println!("{:?}", event);
//!         Ok(())
//!     }
//! }
//!
//! // Application code drains a Pipeline's output into the sink
//! let mut sink = StdoutSink;
//! match pipeline.run(event) {
//!     ProcessResult::Continue(event) => sink.send(&event)?,
//!     ProcessResult::Drop(_) | ProcessResult::Error(_) => {}
//! }
//! ```
//!
//! # Firing an [`crate::processing::action::Action`] as a side effect
//!
//! A `Sink` can fire a response action without any change to this trait —
//! the dependency is just an ordinary constructor-injected field, and any
//! resulting [`crate::processing::action::ActionOutcome`] can be turned back
//! into an event and shipped through a `Sink` for audit, same as any other
//! event.
//!
//! ```rust,no_compile,no_run
//! use std::sync::Arc;
//! use crate::processing::action::ActionRegistry;
//!
//! struct AlertingSink {
//!     inner: Box<dyn Sink>,
//!     actions: Arc<ActionRegistry>,
//! }
//!
//! impl Sink for AlertingSink {
//!     fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!         self.inner.send(event)?;
//!
//!         if let Some(ip) = event.get_field("client.ip") {
//!             let mut params = std::collections::HashMap::new();
//!             params.insert("ip".to_string(), ip.clone());
//!
//!             // Fans out to every provider registered under "block_ip" —
//!             // this Sink knows nothing about which components exist.
//!             for result in self.actions.invoke("block_ip", &params) {
//!                 if let Ok(outcome) = result.result {
//!                     self.inner.send(&outcome.into_event("block_ip", &result.provider, &params))?;
//!                 }
//!             }
//!         }
//!         Ok(())
//!     }
//! }
//! ```

use crate::event::Event;

/// Framework interface for event output destinations.
///
/// A `Sink` is a trait rather than an `fn` pointer (unlike
/// [`crate::ingest::parser::LogParser`]) because most real destinations need
/// to hold state — a socket, a file handle, a batching buffer — which a bare
/// function pointer cannot capture.
pub trait Sink {
    /// Send a single event to this sink.
    fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Flush any buffered events. The default implementation is a no-op, for
    /// sinks that write through immediately.
    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Origin;
    use crate::event::core::RawData;
    use crate::event::field::Timestamp;

    #[derive(Default)]
    struct CollectingSink {
        sent: Vec<String>,
        flushed: bool,
    }

    impl Sink for CollectingSink {
        fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.sent.push(event.raw_data().as_string());
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.flushed = true;
            Ok(())
        }
    }

    fn sample_event(text: &str) -> Event {
        Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_hostname("test-host"),
            RawData::from_text(text),
        )
    }

    #[test]
    fn test_sink_receives_sent_events() {
        let mut sink = CollectingSink::default();
        sink.send(&sample_event("first")).unwrap();
        sink.send(&sample_event("second")).unwrap();

        assert_eq!(sink.sent, vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn test_sink_default_flush_is_overridable() {
        let mut sink = CollectingSink::default();
        assert!(!sink.flushed);
        sink.flush().unwrap();
        assert!(sink.flushed);
    }

    #[test]
    fn test_sink_is_usable_as_trait_object() {
        let mut sink: Box<dyn Sink> = Box::new(CollectingSink::default());
        sink.send(&sample_event("boxed")).unwrap();
    }
}
