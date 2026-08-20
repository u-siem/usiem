//! A minimal internal logging facade — deliberately dependency-free.
//!
//! Mirrors the shape of the widely-used `log` crate (a global logger plus
//! level filtering) but implemented in-house, per this crate's
//! minimal-dependency philosophy (only `time` and `regex` today). Like the
//! [`crate::processing::sink::Sink`]/[`crate::ingest::collector::Collector`]
//! pattern, this is a framework interface with no bundled implementation:
//! nothing is emitted unless a consuming application installs a [`Logger`]
//! via [`set_logger`].
//!
//! Internal call sites use the [`log_error!`](crate::log_error),
//! [`log_warn!`](crate::log_warn), [`log_info!`](crate::log_info),
//! [`log_debug!`](crate::log_debug), and [`log_trace!`](crate::log_trace)
//! macros, which skip formatting the message entirely when the level is
//! disabled or no logger is installed.
//!
//! # Usage pattern
//!
//! ```
//! use usiem::observability::{Level, Logger, Record, set_logger, set_max_level};
//!
//! struct StderrLogger;
//! impl Logger for StderrLogger {
//!     fn log(&self, record: &Record<'_>) {
//!         eprintln!("[{:?}] {}: {}", record.level, record.target, record.message);
//!     }
//! }
//!
//! set_logger(StderrLogger);
//! set_max_level(Level::Debug);
//! ```

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

/// Severity of a log record, ordered from most (`Error`) to least (`Trace`) severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

/// A single log record passed to an installed [`Logger`].
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    /// Severity of this record.
    pub level: Level,
    /// Where the record originated — typically a module, stage, or parser name.
    pub target: &'static str,
    /// The formatted message.
    pub message: &'a str,
}

/// Implemented by applications that want to receive this crate's internal
/// log records. There is no bundled implementation — install one with
/// [`set_logger`], or nothing is emitted.
pub trait Logger: Send + Sync {
    /// Handle a single log record.
    fn log(&self, record: &Record<'_>);
}

static LOGGER: OnceLock<Box<dyn Logger>> = OnceLock::new();
static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Install the global logger.
///
/// Returns `true` if this call installed it, `false` if a logger was already
/// installed (in which case `logger` is dropped and the existing one keeps
/// receiving records). Intended to be called once, at application startup.
pub fn set_logger<L: Logger + 'static>(logger: L) -> bool {
    LOGGER.set(Box::new(logger)).is_ok()
}

/// Set the maximum level that will be passed to the installed [`Logger`].
/// Records more verbose than this are never even formatted.
pub fn set_max_level(level: Level) {
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// The current maximum level (defaults to [`Level::Info`]).
pub fn max_level() -> Level {
    match MAX_LEVEL.load(Ordering::Relaxed) {
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    }
}

/// Returns `true` if a record at `level` would currently be emitted. Call
/// sites doing non-trivial formatting should check this first — the
/// `log_*!` macros already do.
pub fn is_enabled(level: Level) -> bool {
    level <= max_level() && LOGGER.get().is_some()
}

/// Emit a log record if `level` is enabled and a logger is installed.
///
/// Prefer the `log_error!`/`log_warn!`/etc. macros, which skip formatting
/// the message entirely when disabled; this function still takes an
/// already-formatted `&str`.
pub fn log(level: Level, target: &'static str, message: &str) {
    if !is_enabled(level) {
        return;
    }
    if let Some(logger) = LOGGER.get() {
        logger.log(&Record {
            level,
            target,
            message,
        });
    }
}

/// Emit an [`Level::Error`] record, formatting the message lazily.
#[macro_export]
macro_rules! log_error {
    ($target:expr, $($arg:tt)+) => {
        if $crate::observability::is_enabled($crate::observability::Level::Error) {
            $crate::observability::log($crate::observability::Level::Error, $target, &format!($($arg)+));
        }
    };
}

/// Emit a [`Level::Warn`] record, formatting the message lazily.
#[macro_export]
macro_rules! log_warn {
    ($target:expr, $($arg:tt)+) => {
        if $crate::observability::is_enabled($crate::observability::Level::Warn) {
            $crate::observability::log($crate::observability::Level::Warn, $target, &format!($($arg)+));
        }
    };
}

/// Emit a [`Level::Info`] record, formatting the message lazily.
#[macro_export]
macro_rules! log_info {
    ($target:expr, $($arg:tt)+) => {
        if $crate::observability::is_enabled($crate::observability::Level::Info) {
            $crate::observability::log($crate::observability::Level::Info, $target, &format!($($arg)+));
        }
    };
}

/// Emit a [`Level::Debug`] record, formatting the message lazily.
#[macro_export]
macro_rules! log_debug {
    ($target:expr, $($arg:tt)+) => {
        if $crate::observability::is_enabled($crate::observability::Level::Debug) {
            $crate::observability::log($crate::observability::Level::Debug, $target, &format!($($arg)+));
        }
    };
}

/// Emit a [`Level::Trace`] record, formatting the message lazily.
#[macro_export]
macro_rules! log_trace {
    ($target:expr, $($arg:tt)+) => {
        if $crate::observability::is_enabled($crate::observability::Level::Trace) {
            $crate::observability::log($crate::observability::Level::Trace, $target, &format!($($arg)+));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CollectingLogger {
        records: Mutex<Vec<(Level, &'static str, String)>>,
    }

    impl Logger for &'static CollectingLogger {
        fn log(&self, record: &Record<'_>) {
            self.records.lock().unwrap().push((
                record.level,
                record.target,
                record.message.to_string(),
            ));
        }
    }

    // A OnceLock-backed global test logger, since `set_logger` is a
    // process-wide singleton and Rust test binaries run tests in threads
    // within the same process. Using a single shared static keeps this test
    // module self-contained without requiring `--test-threads=1`.
    static TEST_LOGGER: CollectingLogger = CollectingLogger {
        records: Mutex::new(Vec::new()),
    };

    #[test]
    fn test_level_ordering_matches_log_crate_convention() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert!(Level::Debug < Level::Trace);
    }

    // Both assertions live in one test function (rather than two) because
    // they share process-global state (`LOGGER`/`MAX_LEVEL`) that would
    // otherwise race under Rust's default parallel test runner.
    #[test]
    fn test_logger_installation_and_level_filtering() {
        // Level filtering holds even before/without regard to whether a
        // logger is installed: a level less severe than max_level is never enabled.
        set_max_level(Level::Error);
        assert!(!is_enabled(Level::Trace));

        set_logger(&TEST_LOGGER);
        set_max_level(Level::Debug);

        crate::log_info!("test_target", "hello {}", "world");
        crate::log_trace!("test_target", "should not appear");

        let records = TEST_LOGGER.records.lock().unwrap();
        assert!(
            records
                .iter()
                .any(|(level, target, msg)| *level == Level::Info
                    && *target == "test_target"
                    && msg == "hello world")
        );
        assert!(!records.iter().any(|(_, _, msg)| msg == "should not appear"));
    }
}
