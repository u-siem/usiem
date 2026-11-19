//! End-to-end example: parse raw logs, run them through a processing
//! pipeline, correlate repeated failures into a `Signal`, and print
//! everything — wiring together `LogParser`/`ParserRegistry`,
//! `Pipeline`/`Processor`, `Signal` and `observability`, plus a correlation
//! rule (`FailedLoginCounter` below) that is deliberately
//! *not* part of the crate's API — this crate has no correlation/rule-engine
//! type of its own, so detecting "3 failed logins within 60s" is just plain
//! application code, the same as `tag_internal_ip` below.
//!
//! Run with: `cargo run --example basic_pipeline`

use std::collections::HashMap;
use usiem::event::Event;
use usiem::observability::Record;
use usiem::prelude::*;

/// A trivial output that prints events to stdout. A real application writes
/// to its event store (a file, an index, a queue).
struct StdoutSink;

impl StdoutSink {
    fn send(&mut self, event: &Event) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event_type = event
            .get_field("event_type")
            .and_then(|f| f.as_str())
            .unwrap_or("unknown");
        println!("[sink] event_type={event_type} origin={:?}", event.origin());
        Ok(())
    }
}

/// A trivial `Logger` that prints uSIEM's internal log records to stderr.
struct StderrLogger;

impl Logger for StderrLogger {
    fn log(&self, record: &Record<'_>) {
        eprintln!("[{:?}] {}: {}", record.level, record.target, record.message);
    }
}

/// A time-windowed occurrence counter, keyed by an arbitrary string (here, a
/// client IP) — ordinary application code, not a usiem type. This crate has
/// no correlation/rule-engine API: how you decide "3 failed logins in 60s"
/// is entirely up to you, and this is just one way to do it. A real,
/// long-running deployment would want to bound `occurrences`' growth (an
/// LRU cache, a TTL sweep, a cap on distinct keys) — skipped here since this
/// example only ever sees a handful of keys.
struct FailedLoginCounter {
    threshold: usize,
    window_nanos: i64,
    occurrences: HashMap<String, Vec<Timestamp>>,
}

impl FailedLoginCounter {
    fn new(threshold: usize, window_nanos: i64) -> Self {
        Self {
            threshold,
            window_nanos,
            occurrences: HashMap::new(),
        }
    }

    /// Record an occurrence for `key` at `timestamp` and report whether
    /// `threshold` occurrences have now happened within `window_nanos` of
    /// each other.
    fn record(&mut self, key: &str, timestamp: Timestamp) -> bool {
        let entries = self.occurrences.entry(key.to_string()).or_default();
        entries.push(timestamp);
        entries.retain(|t| timestamp.duration_since(t) <= self.window_nanos);
        entries.len() >= self.threshold
    }

    fn count(&self, key: &str) -> usize {
        self.occurrences.get(key).map(|v| v.len()).unwrap_or(0)
    }
}

/// A pipeline stage that flags whether the client IP looks like a private address.
fn tag_internal_ip(mut event: Event) -> ProcessResult {
    let is_internal = event
        .get_field("client.ip")
        .and_then(|f| f.as_str())
        .map(|ip| ip.starts_with("10.") || ip.starts_with("192.168."))
        .unwrap_or(false);
    event.add_field("client.ip.is_internal", FieldValue::Bool(is_internal));
    ProcessResult::Continue(event)
}

fn main() {
    // Observability is opt-in: nothing is emitted until a logger is installed.
    set_logger(StderrLogger);
    set_max_level(LogLevel::Debug);

    let mut registry = ParserRegistry::new();
    registry.register(apache_common_parser());
    registry.register(cef_parser());

    let mut pipeline = Pipeline::new();
    pipeline.add_stage(Processor::new(
        "tag_internal_ip",
        "Flags client IPs from private ranges",
        tag_internal_ip,
    ));

    let mut sink = StdoutSink;
    let mut failed_logins = FailedLoginCounter::new(3, 60_000_000_000); // fire at 3 within 60s

    let logs = [
        r#"192.168.1.50 - - [25/Dec/2023:10:00:00 +0000] "GET /login HTTP/1.1" 401 512"#,
        r#"192.168.1.50 - - [25/Dec/2023:10:00:10 +0000] "GET /login HTTP/1.1" 401 512"#,
        r#"192.168.1.50 - - [25/Dec/2023:10:00:20 +0000] "GET /login HTTP/1.1" 401 512"#,
        "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=203.0.113.5 act=blocked",
        // Not recognized by any registered parser — triggers the internal
        // "no parser matched" warning below (see observability output on stderr).
        "this is not a log line any registered parser understands",
    ];

    for log in logs {
        let raw = RawEvent::from_log(log, "access.log");
        let event = match registry.parse(raw) {
            ParseResult::Success(event) => event,
            ParseResult::NoMatch(_) => {
                println!("[main] no parser matched, skipping: {log}");
                continue;
            }
            other => {
                println!("[main] parse error/discard: {other:?}");
                continue;
            }
        };

        let event = match pipeline.run(event) {
            ProcessResult::Continue(event) => event,
            other => {
                println!("[main] pipeline stopped: {other:?}");
                continue;
            }
        };

        // Correlate: 3+ HTTP 401s from the same client IP within the window.
        let is_401 = event
            .get_field("http.response.status_code")
            .and_then(|f| f.as_i64())
            == Some(401);
        if is_401
            && let Some(client_ip) = event.get_field("client.ip").and_then(|f| f.as_str())
            && failed_logins.record(client_ip, event.original_time())
        {
            // A Signal states a narrow fact ("this looks suspicious") — not
            // itself a claim that an analyst should look at it. A
            // `FailedLoginCounter` trip is exactly the kind of evaluation a
            // Signal exists to carry, optionally alongside enrichment
            // context (here stood in for by `with_context`, in place of a
            // real threat-intel or `GeoIpDataset` lookup).
            let signal = Signal::new(
                "repeated_failed_login",
                client_ip,
                Severity::High,
                Confidence::new(80),
                LocalizedMessage::new(
                    "auth.brute_force_threshold",
                    "en-US",
                    format!("3+ failed logins from {client_ip} within 60s"),
                )
                .with_param("client_ip", client_ip.to_string())
                .with_param("count", failed_logins.count(client_ip) as u64),
                event.original_time(),
            )
            .with_techniques(["T1110"])
            .with_source_events([EventRef::from(&event)])
            .with_context("threat_intel.note", "matches known brute-force pattern");

            // Whether this is worth an analyst's attention (an alert or
            // incident, with its own workflow) is the application's call.
            sink.send(&signal.into_event()).unwrap();
        }

        sink.send(&event).unwrap();
    }
}
