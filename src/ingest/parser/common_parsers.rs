use crate::event::RawEvent;
#[cfg(feature = "json")]
use crate::ingest::parser::err::ParsingError;
use crate::ingest::parser::{LogParser, result::ParseResult};
use regex::Regex;
use std::sync::LazyLock;

/// Common log format parsers for standard formats

// Static regex patterns for maximum performance
static APACHE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?$"#)
        .expect("Invalid Apache log regex")
});

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

        // TODO: Parse timestamp from captures[4] and set raw_event.timestamp

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
    match serde_json::from_str::<serde_json::Value>(raw_event.log_text.trim()) {
        Ok(json) => {
            // Set event type from JSON or default to "json_log"
            raw_event.event_type = json
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("json_log")
                .to_string();

            // TODO: Extract timestamp from JSON if present and set raw_event.timestamp

            // Flatten JSON into dot-notation fields
            if let serde_json::Value::Object(map) = json {
                for (key, value) in map {
                    match value {
                        serde_json::Value::String(s) => {
                            raw_event.insert_field(key, s);
                        }
                        serde_json::Value::Number(n) => {
                            if let Some(i) = n.as_i64() {
                                raw_event.insert_field(key, i);
                            } else if let Some(f) = n.as_f64() {
                                raw_event.insert_field(key, f);
                            }
                        }
                        serde_json::Value::Bool(b) => {
                            raw_event.insert_field(key, b);
                        }
                        _ => {
                            // For complex objects, store as string
                            raw_event.insert_field(key, value.to_string());
                        }
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

/// Windows Event Log format parser function
/// Example: 2023-12-25 10:00:00.000 [Information] Event ID: 4624 - An account was successfully logged on
pub fn parse_windows_event(mut raw_event: RawEvent) -> ParseResult {
    // Check if the log matches the Windows Event Log pattern
    let parsed_fields = {
        let log_text = &raw_event.log_text;
        if let Some(captures) = WINDOWS_REGEX.captures(log_text) {
            Some((
                captures.get(2).unwrap().as_str().to_string(),
                captures.get(3).unwrap().as_str().to_string(),
                captures.get(4).unwrap().as_str().to_string(),
            ))
        } else {
            None
        }
    };

    if let Some((log_level, event_id_str, message)) = parsed_fields {
        // TODO: Parse timestamp from first capture group and set raw_event.timestamp

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
            }
            _ => panic!("Expected successful parse"),
        }
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
            }
            _ => panic!("Expected successful parse"),
        }
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
