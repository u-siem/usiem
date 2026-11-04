use crate::event::RawEvent;
#[cfg(feature = "json")]
use crate::event::field::FieldValue;
use crate::event::field::Timestamp;
#[cfg(feature = "json")]
use crate::ingest::parser::err::ParsingError;
use crate::ingest::parser::{LogParser, result::ParseResult};
use regex::Regex;
use std::sync::LazyLock;

// Common log format parsers for standard formats

// Static regex patterns for maximum performance
static APACHE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?$"#)
        .expect("Invalid Apache log regex")
});

// Format: 25/Dec/2023:10:00:00 +0000
const APACHE_TIME_FORMAT: &[time::format_description::BorrowedFormatItem<'_>] = time::macros::format_description!(
    "[day]/[month repr:short]/[year]:[hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
);

/// Apache Combined Log Format parser function
/// Example: 127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET / HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"
pub fn parse_apache_common(mut raw_event: RawEvent) -> ParseResult {
    if let Some(captures) = APACHE_REGEX.captures(&raw_event.log_text) {
        // Extract all data first to avoid borrow conflicts
        let client_ip = captures.get(1).unwrap().as_str().to_string();
        let method_uri = captures.get(5).unwrap().as_str().to_string();
        let status_code = captures
            .get(6)
            .unwrap()
            .as_str()
            .parse::<i64>()
            .unwrap_or(0);
        let response_bytes = captures.get(7).unwrap().as_str().to_string();
        let referer = captures.get(8).map(|m| m.as_str().to_string());
        let user_agent = captures.get(9).map(|m| m.as_str().to_string());

        let timestamp_str = captures.get(4).unwrap().as_str();
        if let Ok(dt) = time::OffsetDateTime::parse(timestamp_str, APACHE_TIME_FORMAT)
            && let Ok(nanos) = dt.unix_timestamp_nanos().try_into()
        {
            raw_event.original_time = Timestamp::from_nanos(nanos);
        }

        // Set event type and extract fields
        raw_event.insert_field("event_type", "web_access".to_string());
        raw_event.insert_field("client.ip", client_ip);
        raw_event.insert_field("http.request.method_uri", method_uri);
        raw_event.insert_field("http.response.status_code", status_code);
        raw_event.insert_field("http.response.bytes", response_bytes);

        if let Some(ref_val) = referer {
            raw_event.insert_field("http.request.referer", ref_val);
        }
        if let Some(ua_val) = user_agent {
            raw_event.insert_field("user_agent.original", ua_val);
        }

        // Convert RawEvent to Event and return Success
        let event = raw_event.into_event();
        ParseResult::Success(event)
    } else {
        // Return the original RawEvent unchanged for further processing
        ParseResult::NoMatch(raw_event)
    }
}

/// Create Apache Common Log parser
pub fn apache_common_parser() -> LogParser {
    LogParser::new(
        "apache_common",
        "Apache Common/Combined Log Format",
        "Parses Apache access logs in Common or Combined format",
        parse_apache_common,
    )
}

/// JSON log parser function for structured logs
#[cfg(feature = "json")]
pub fn parse_json(mut raw_event: RawEvent) -> ParseResult {
    // Only a JSON object is a structured log; anything else is some other
    // parser's input, not malformed JSON.
    if !raw_event.log_text.trim_start().starts_with('{') {
        return ParseResult::NoMatch(raw_event);
    }
    match serde_json::from_str::<serde_json::Value>(raw_event.log_text.trim()) {
        Ok(json) => {
            // Set event type from JSON or default to "json_log"
            let event_type = json
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("json_log")
                .to_string();

            // Extract timestamp from a "timestamp" or "@timestamp" field if present and parseable
            let parsed_timestamp = json
                .get("timestamp")
                .or_else(|| json.get("@timestamp"))
                .and_then(|v| v.as_str())
                .and_then(|s| Timestamp::from_rfc3339(s).ok());

            if let Some(ts) = parsed_timestamp {
                raw_event.original_time = ts;
            }

            raw_event.insert_field("event_type", event_type);

            // Convert top-level JSON keys into fields, recursing into nested
            // objects/arrays as FieldValue::Object/Array (see
            // FieldValue::from_json) instead of stringifying them.
            if let serde_json::Value::Object(map) = json {
                for (key, value) in map {
                    if let Some(field_value) = FieldValue::from_json(value) {
                        raw_event.insert_field(key, field_value);
                    }
                }
            }

            // Convert RawEvent to Event and return Success
            let event = raw_event.into_event();
            ParseResult::Success(event)
        }
        Err(e) => ParseResult::Error(ParsingError::format_error(format!("Invalid JSON: {}", e))),
    }
}

/// Create JSON parser
#[cfg(feature = "json")]
pub fn json_parser() -> LogParser {
    LogParser::new(
        "json",
        "JSON Log Parser",
        "Parses JSON-formatted log entries",
        parse_json,
    )
}

// Static Windows Event Log regex for maximum performance
static WINDOWS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) \[(\w+)\] Event ID: (\d+) - (.*)$"#)
        .expect("Invalid Windows Event Log regex")
});

// Format: 2023-12-25 10:00:00.000 (no timezone in this format — treated as UTC)
const WINDOWS_TIME_FORMAT: &[time::format_description::BorrowedFormatItem<'_>] = time::macros::format_description!(
    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
);

/// Windows Event Log format parser function
/// Example: 2023-12-25 10:00:00.000 [Information] Event ID: 4624 - An account was successfully logged on
pub fn parse_windows_event(mut raw_event: RawEvent) -> ParseResult {
    // Check if the log matches the Windows Event Log pattern
    let parsed_fields = {
        let log_text = &raw_event.log_text;
        WINDOWS_REGEX.captures(log_text).map(|captures| {
            (
                captures.get(1).unwrap().as_str().to_string(),
                captures.get(2).unwrap().as_str().to_string(),
                captures.get(3).unwrap().as_str().to_string(),
                captures.get(4).unwrap().as_str().to_string(),
            )
        })
    };

    if let Some((timestamp_str, log_level, event_id_str, message)) = parsed_fields {
        if let Ok(dt) = time::PrimitiveDateTime::parse(&timestamp_str, WINDOWS_TIME_FORMAT)
            && let Ok(nanos) = dt.assume_utc().unix_timestamp_nanos().try_into()
        {
            raw_event.original_time = Timestamp::from_nanos(nanos);
        }

        // Set event type and process fields
        raw_event.insert_field("event_type", "windows_event".to_string());
        raw_event.insert_field("log.level", log_level);
        if let Ok(event_id) = event_id_str.parse::<i64>() {
            raw_event.insert_field("winlog.event_id", event_id);
        }
        raw_event.insert_field("message", message);

        // Convert RawEvent to Event and return Success
        let event = raw_event.into_event();
        ParseResult::Success(event)
    } else {
        // Return the original RawEvent unchanged for further processing
        ParseResult::NoMatch(raw_event)
    }
}

/// Create Windows Event Log parser
pub fn windows_event_parser() -> LogParser {
    LogParser::new(
        "windows_event_log",
        "Windows Event Log",
        "Parses Windows Event Log format",
        parse_windows_event,
    )
}

// Static regex for the CEF header: `CEF:Version|Vendor|Product|Version|ClassId|Name|Severity|Extension`
static CEF_HEADER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")
        .expect("Invalid CEF header regex")
});

// Matches an extension key (`key=`) so values containing spaces can be
// recovered as "everything up to the next key=".
static CEF_EXTENSION_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9_.]+)=").expect("Invalid CEF extension key regex"));

/// Parse a CEF extension (`key1=value1 key2=value2 ...`) into key/value pairs.
///
/// CEF values may contain spaces, so a plain `split_whitespace` would break
/// on multi-word values (e.g. `msg=connection refused`). Instead, each
/// value is taken as everything between one `key=` match and the next.
fn parse_cef_extension(extension: &str) -> Vec<(String, String)> {
    let matches: Vec<_> = CEF_EXTENSION_KEY_REGEX.find_iter(extension).collect();
    let mut pairs = Vec::with_capacity(matches.len());

    for (i, m) in matches.iter().enumerate() {
        let key = &extension[m.start()..m.end() - 1]; // strip the trailing '='
        let value_start = m.end();
        let value_end = matches
            .get(i + 1)
            .map(|next| next.start())
            .unwrap_or(extension.len());
        let value = extension[value_start..value_end].trim();
        pairs.push((key.to_string(), value.to_string()));
    }

    pairs
}

/// Common Event Format (CEF) parser function
/// Example: CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.2 dst=2.1.2.2 act=blocked
pub fn parse_cef(mut raw_event: RawEvent) -> ParseResult {
    if let Some(captures) = CEF_HEADER_REGEX.captures(raw_event.log_text.trim()) {
        let version = captures.get(1).unwrap().as_str().to_string();
        let device_vendor = captures.get(2).unwrap().as_str().to_string();
        let device_product = captures.get(3).unwrap().as_str().to_string();
        let device_version = captures.get(4).unwrap().as_str().to_string();
        let device_event_class_id = captures.get(5).unwrap().as_str().to_string();
        let name = captures.get(6).unwrap().as_str().to_string();
        let severity = captures.get(7).unwrap().as_str().to_string();
        let extension_pairs = parse_cef_extension(captures.get(8).unwrap().as_str());

        // CEF's `rt` extension field (receipt time) is epoch milliseconds when numeric.
        if let Some((_, rt)) = extension_pairs.iter().find(|(k, _)| k == "rt")
            && let Ok(millis) = rt.parse::<i64>()
        {
            raw_event.original_time = Timestamp::from_millis(millis);
        }

        raw_event.insert_field("event_type", "cef".to_string());
        raw_event.insert_field("cef.version", version);
        raw_event.insert_field("cef.device_vendor", device_vendor);
        raw_event.insert_field("cef.device_product", device_product);
        raw_event.insert_field("cef.device_version", device_version);
        raw_event.insert_field("cef.device_event_class_id", device_event_class_id);
        raw_event.insert_field("cef.name", name);
        if let Ok(severity_num) = severity.parse::<i64>() {
            raw_event.insert_field("cef.severity", severity_num);
        }

        for (key, value) in extension_pairs {
            raw_event.insert_field(format!("cef.extension.{}", key), value);
        }

        let event = raw_event.into_event();
        ParseResult::Success(event)
    } else {
        ParseResult::NoMatch(raw_event)
    }
}

/// Create CEF (Common Event Format) parser
pub fn cef_parser() -> LogParser {
    LogParser::new(
        "cef",
        "Common Event Format (CEF)",
        "Parses ArcSight Common Event Format (CEF) log entries",
        parse_cef,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::parser::registry::ParserRegistry;

    #[test]
    fn test_apache_parser() {
        let parser = apache_common_parser();
        let log = r#"127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0""#;

        let result = (parser.parse_fn)(RawEvent::from_log(log, "access.log"));
        match result {
            ParseResult::Success(event) => {
                assert_eq!(
                    event.fields.get("event_type").unwrap().as_str().unwrap(),
                    "web_access"
                );
                assert_eq!(
                    event.fields.get("client.ip").unwrap().as_str().unwrap(),
                    "127.0.0.1"
                );
                assert_eq!(
                    event.original_time(),
                    Timestamp::from_rfc3339("2023-12-25T10:00:00Z").unwrap()
                );
            }
            _ => panic!("Expected successful parse"),
        }
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_parser_passes_on_non_json_text() {
        let raw = RawEvent::from_log("sshd: Accepted publickey for bob", "host");
        assert!(matches!(parse_json(raw), ParseResult::NoMatch(_)));
        let broken = RawEvent::from_log("{\"unterminated\": ", "host");
        assert!(matches!(parse_json(broken), ParseResult::Error(_)));
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_json_parser() {
        let parser = json_parser();
        let log = r#"{"timestamp": "2023-12-25T10:00:00Z", "level": "info", "message": "Test log", "user": "alice"}"#;

        let result = (parser.parse_fn)(RawEvent::from_log(log, "app.log"));
        match result {
            ParseResult::Success(event) => {
                assert_eq!(event.fields.get("level").unwrap().as_str().unwrap(), "info");
                assert_eq!(event.fields.get("user").unwrap().as_str().unwrap(), "alice");
                assert_eq!(
                    event.original_time(),
                    Timestamp::from_rfc3339("2023-12-25T10:00:00Z").unwrap()
                );
            }
            _ => panic!("Expected successful parse"),
        }
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_json_parser_recurses_into_nested_objects_and_arrays() {
        let parser = json_parser();
        let log = r#"{
            "user": {"id": 123, "name": "alice"},
            "tags": ["suspicious", 42, true]
        }"#;

        let result = (parser.parse_fn)(RawEvent::from_log(log, "app.log"));
        match result {
            ParseResult::Success(event) => {
                match event.fields.get("user") {
                    Some(FieldValue::Object(user)) => {
                        assert_eq!(user.get("id").and_then(|v| v.as_i64()), Some(123));
                        assert_eq!(user.get("name").and_then(|v| v.as_str()), Some("alice"));
                    }
                    other => panic!("expected user to be a nested Object, got {other:?}"),
                }

                match event.fields.get("tags") {
                    Some(FieldValue::Array(tags)) => {
                        assert_eq!(tags.len(), 3);
                        assert_eq!(tags[0].as_str(), Some("suspicious"));
                        assert_eq!(tags[1].as_i64(), Some(42));
                        assert_eq!(tags[2].as_bool(), Some(true));
                    }
                    other => panic!("expected tags to be an Array, got {other:?}"),
                }
            }
            other => panic!("Expected successful parse, got {other:?}"),
        }
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_json_parser_drops_nulls_instead_of_stringifying() {
        let parser = json_parser();
        let log = r#"{"user": "alice", "session_id": null, "meta": {"note": null, "kept": 1}}"#;

        let result = (parser.parse_fn)(RawEvent::from_log(log, "app.log"));
        match result {
            ParseResult::Success(event) => {
                assert!(!event.fields.contains_key("session_id"));

                match event.fields.get("meta") {
                    Some(FieldValue::Object(meta)) => {
                        assert!(!meta.contains_key("note"));
                        assert_eq!(meta.get("kept").and_then(|v| v.as_i64()), Some(1));
                    }
                    other => panic!("expected meta to be a nested Object, got {other:?}"),
                }
            }
            other => panic!("Expected successful parse, got {other:?}"),
        }
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_json_parser_large_u64_does_not_lose_precision_to_f64() {
        let parser = json_parser();
        // Larger than i64::MAX but fits u64 — previously fell through to f64
        // (as_i64() -> None, then as_f64() -> lossy), since the old code
        // never tried as_u64() at all.
        let log = r#"{"big_id": 18446744073709551615}"#;

        let result = (parser.parse_fn)(RawEvent::from_log(log, "app.log"));
        match result {
            ParseResult::Success(event) => {
                assert_eq!(
                    event.fields.get("big_id").and_then(|v| v.as_u64()),
                    Some(u64::MAX)
                );
            }
            other => panic!("Expected successful parse, got {other:?}"),
        }
    }

    #[test]
    fn test_cef_parser() {
        let parser = cef_parser();
        let log = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.2 dst=2.1.2.2 act=blocked cs1Label=Message cs1=Detected worm";

        let result = (parser.parse_fn)(RawEvent::from_log(log, "cef.log"));
        match result {
            ParseResult::Success(event) => {
                assert_eq!(
                    event.fields.get("event_type").unwrap().as_str().unwrap(),
                    "cef"
                );
                assert_eq!(
                    event
                        .fields
                        .get("cef.device_vendor")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "Security"
                );
                assert_eq!(
                    event
                        .fields
                        .get("cef.device_product")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "threatmanager"
                );
                assert_eq!(
                    event.fields.get("cef.severity").unwrap().as_i64().unwrap(),
                    10
                );
                assert_eq!(
                    event
                        .fields
                        .get("cef.extension.src")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "10.0.0.2"
                );
                // "Detected worm" contains a space; the extension parser must
                // not truncate it at the first space.
                assert_eq!(
                    event
                        .fields
                        .get("cef.extension.cs1")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "Detected worm"
                );
            }
            other => panic!("Expected successful parse, got {other:?}"),
        }
    }

    #[test]
    fn test_cef_parser_extracts_receipt_time() {
        let parser = cef_parser();
        let log = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|rt=1382967645000 src=10.0.0.2";

        let result = (parser.parse_fn)(RawEvent::from_log(log, "cef.log"));
        match result {
            ParseResult::Success(event) => {
                assert_eq!(event.original_time(), Timestamp::from_millis(1382967645000));
            }
            other => panic!("Expected successful parse, got {other:?}"),
        }
    }

    #[test]
    fn test_cef_parser_no_match_on_non_cef_log() {
        let parser = cef_parser();
        let log = "not a cef log line";

        let result = (parser.parse_fn)(RawEvent::from_log(log, "cef.log"));
        assert!(matches!(result, ParseResult::NoMatch(_)));
    }

    #[test]
    fn test_parser_registry_with_multiple_parsers() {
        let mut registry = ParserRegistry::new();
        registry.register(apache_common_parser());
        registry.register(windows_event_parser());

        // Test Apache parser
        let apache_log = r#"127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET / HTTP/1.1" 200 2326"#;
        let event = RawEvent::from_log(apache_log, "access.log");
        let result = registry.parse(event);
        match result {
            ParseResult::Success(event) => {
                assert_eq!(
                    event.fields.get("event_type").unwrap().as_str().unwrap(),
                    "web_access"
                );
            }
            _ => panic!("Expected successful parse"),
        }
    }
}
