use crate::event::field::Timestamp;
use crate::event::{Origin, RawEvent};
use crate::ingest::parser::transport::{TransportParser, TransportResult};
use regex::Regex;
use std::sync::LazyLock;

// Syslog transport parsers for RFC3164 and RFC5424

// Static regex for RFC3164 syslog format
static SYSLOG_RFC3164_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^<(\d+)>(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:\[]+)(?:\[(\d+)\])?: (.*)$"#)
        .expect("Invalid Syslog RFC3164 regex")
});

// Static regex for RFC5424 syslog format
static SYSLOG_RFC5424_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (\[.*?\])? (.*)$"#)
        .expect("Invalid Syslog RFC5424 regex")
});

// Static regex for parsing structured data elements
// Matches [SD-ID params...] where SD-ID is the first non-space token
static STRUCTURED_DATA_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\[(\S+)([^\]]*)\]"#).expect("Invalid structured data regex"));

// Static regex for parsing structured data parameters (param="value")
static STRUCTURED_DATA_PARAM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r##"(\S+)="([^"]*)""##).expect("Invalid structured data parameter regex")
});

/// RFC3164 timestamps omit the year (e.g. "Dec 25 10:00:00") and carry no
/// timezone; this assumes the current UTC year and treats the time as UTC.
fn parse_rfc3164_timestamp(raw: &str) -> Option<Timestamp> {
    let mut parts = raw.split_whitespace();
    let month = match parts.next()? {
        "Jan" => time::Month::January,
        "Feb" => time::Month::February,
        "Mar" => time::Month::March,
        "Apr" => time::Month::April,
        "May" => time::Month::May,
        "Jun" => time::Month::June,
        "Jul" => time::Month::July,
        "Aug" => time::Month::August,
        "Sep" => time::Month::September,
        "Oct" => time::Month::October,
        "Nov" => time::Month::November,
        "Dec" => time::Month::December,
        _ => return None,
    };
    let day: u8 = parts.next()?.parse().ok()?;
    let mut time_parts = parts.next()?.split(':');
    let hour: u8 = time_parts.next()?.parse().ok()?;
    let minute: u8 = time_parts.next()?.parse().ok()?;
    let second: u8 = time_parts.next()?.parse().ok()?;

    let year = time::OffsetDateTime::now_utc().year();
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let time_of_day = time::Time::from_hms(hour, minute, second).ok()?;
    let nanos = time::PrimitiveDateTime::new(date, time_of_day)
        .assume_utc()
        .unix_timestamp_nanos();

    nanos.try_into().ok().map(Timestamp::from_nanos)
}

/// Syslog RFC3164 transport parser
/// Extracts syslog transport metadata and isolates message body for content parsing
/// Example: <34>Dec 25 10:00:00 hostname programname[1234]: This is a message
pub fn parse_syslog_rfc3164_transport(log_text: &str, source: Origin) -> TransportResult {
    if let Some(captures) = SYSLOG_RFC3164_REGEX.captures(log_text) {
        let priority_str = captures.get(1).unwrap().as_str();
        let timestamp_str = captures.get(2).unwrap().as_str();
        let hostname = captures.get(3).unwrap().as_str();
        let process_name = captures.get(4).unwrap().as_str();
        let pid_opt = captures.get(5).map(|m| m.as_str());
        let message_body = captures.get(6).unwrap().as_str();

        // Create RawEvent with the message body for content parsing.
        // `timestamp` (arrival time) is ingest time; `original_time` becomes
        // the syslog header's own timestamp when it parses successfully.
        let mut raw_event = RawEvent::new(
            message_body.to_string(), // Body goes to log_text for content parsing
            Timestamp::now(),
            source,
        );
        if let Some(ts) = parse_rfc3164_timestamp(timestamp_str) {
            raw_event.original_time = ts;
        }

        // Store transport metadata in fields
        if let Ok(priority) = priority_str.parse::<u32>() {
            let facility = priority / 8;
            let severity = priority % 8;
            raw_event.insert_field("transport.syslog.priority", priority as i64);
            raw_event.insert_field("transport.syslog.facility", facility as i64);
            raw_event.insert_field("transport.syslog.severity", severity as i64);
        }

        raw_event.insert_field("transport.syslog.version", "rfc3164".to_string());
        raw_event.insert_field("transport.syslog.timestamp", timestamp_str.to_string());
        raw_event.insert_field("transport.syslog.hostname", hostname.to_string());
        raw_event.insert_field("transport.syslog.process", process_name.to_string());

        if let Some(pid_str) = pid_opt
            && let Ok(pid) = pid_str.parse::<i64>()
        {
            raw_event.insert_field("transport.syslog.pid", pid);
        }

        // Store original syslog message for reference
        raw_event.insert_field("transport.original_message", log_text.to_string());

        TransportResult::Success(raw_event)
    } else {
        // Not syslog RFC3164 format - return origin for next parser to try
        TransportResult::NoMatch(source)
    }
}

/// Parse RFC5424 structured data into individual fields
/// Structured data format: [SD-ID param1="value1" param2="value2"][SD-ID2 param3="value3"]
/// Example: [exampleSDID@32473 iut="3" eventSource="Application"][examplePriority@32473 class="high"]
fn parse_structured_data(structured_data: &str, raw_event: &mut RawEvent) {
    // Find all structured data elements [SD-ID params...]
    for captures in STRUCTURED_DATA_REGEX.captures_iter(structured_data) {
        if let (Some(sd_id), Some(params_str)) = (captures.get(1), captures.get(2)) {
            let sd_id_str = sd_id.as_str();
            let params_section = params_str.as_str();

            // Store the SD-ID itself
            let sd_id_field = format!("transport.syslog.structured_data.{}.sd_id", sd_id_str);
            raw_event.insert_field(sd_id_field, sd_id_str.to_string());

            // Parse individual parameters within this structured data element
            for param_captures in STRUCTURED_DATA_PARAM_REGEX.captures_iter(params_section) {
                if let (Some(param_name), Some(param_value)) =
                    (param_captures.get(1), param_captures.get(2))
                {
                    let field_name = format!(
                        "transport.syslog.structured_data.{}.{}",
                        sd_id_str,
                        param_name.as_str()
                    );
                    raw_event.insert_field(field_name, param_value.as_str().to_string());
                }
            }
        }
    }
}

/// Syslog RFC5424 transport parser  
/// Handles structured data and enhanced metadata
/// Example: <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"] An application event log entry
pub fn parse_syslog_rfc5424_transport(log_text: &str, source: Origin) -> TransportResult {
    if let Some(captures) = SYSLOG_RFC5424_REGEX.captures(log_text) {
        let priority_str = captures.get(1).unwrap().as_str();
        let version = captures.get(2).unwrap().as_str();
        let timestamp_str = captures.get(3).unwrap().as_str();
        let hostname = captures.get(4).unwrap().as_str();
        let app_name = captures.get(5).unwrap().as_str();
        let proc_id = captures.get(6).unwrap().as_str();
        let msg_id = captures.get(7).unwrap().as_str();
        let structured_data = captures.get(8).map(|m| m.as_str()).unwrap_or("-");
        let message_body = captures.get(9).unwrap().as_str();

        // Create RawEvent with message body for content parsing.
        // `timestamp` (arrival time) is ingest time; `original_time` becomes
        // the syslog header's own RFC3339 timestamp when it parses successfully.
        let mut raw_event = RawEvent::new(message_body.to_string(), Timestamp::now(), source);
        if let Ok(ts) = Timestamp::from_rfc3339(timestamp_str) {
            raw_event.original_time = ts;
        }

        // Store RFC5424 transport metadata
        if let Ok(priority) = priority_str.parse::<u32>() {
            let facility = priority / 8;
            let severity = priority % 8;
            raw_event.insert_field("transport.syslog.priority", priority as i64);
            raw_event.insert_field("transport.syslog.facility", facility as i64);
            raw_event.insert_field("transport.syslog.severity", severity as i64);
        }

        raw_event.insert_field("transport.syslog.version", version.to_string());
        raw_event.insert_field("transport.syslog.timestamp", timestamp_str.to_string());
        raw_event.insert_field("transport.syslog.hostname", hostname.to_string());
        raw_event.insert_field("transport.syslog.app_name", app_name.to_string());
        raw_event.insert_field("transport.syslog.proc_id", proc_id.to_string());
        raw_event.insert_field("transport.syslog.msg_id", msg_id.to_string());

        // Parse structured data if present
        if structured_data != "-" {
            // Store the raw structured data for reference
            raw_event.insert_field(
                "transport.syslog.structured_data_raw",
                structured_data.to_string(),
            );

            // Parse structured data into individual fields
            parse_structured_data(structured_data, &mut raw_event);
        }

        raw_event.insert_field("transport.original_message", log_text.to_string());

        TransportResult::Success(raw_event)
    } else {
        // Not syslog RFC5424 format - return origin for next parser to try
        TransportResult::NoMatch(source)
    }
}

/// File transport parser
/// Handles file-based log ingestion with file metadata
pub fn parse_file_transport(log_text: &str, source: Origin) -> TransportResult {
    // For files, the entire log line is the content - no transport wrapper to unwrap
    let mut raw_event = RawEvent::new(log_text.to_string(), Timestamp::now(), source.clone());

    // Add file transport metadata
    raw_event.insert_field("transport.type", "file".to_string());

    if let Origin::File(path) = source {
        raw_event.insert_field("transport.file.path", path.clone());

        // Extract file metadata
        if let Some(filename) = path.split(['/', '\\']).next_back() {
            raw_event.insert_field("transport.file.name", filename.to_string());
        }

        if let Some(ext_pos) = path.rfind('.') {
            let extension = &path[ext_pos + 1..];
            raw_event.insert_field("transport.file.extension", extension.to_string());
        }
    }

    // File transport always succeeds - the content parsing will determine format
    TransportResult::Success(raw_event)
}

/// Create Syslog RFC3164 transport parser
pub fn syslog_rfc3164_transport_parser() -> TransportParser {
    TransportParser::new(
        "syslog_rfc3164_transport",
        "Syslog RFC3164 Transport",
        "Extracts RFC3164 syslog transport metadata and isolates message content",
        parse_syslog_rfc3164_transport,
    )
}

/// Create Syslog RFC5424 transport parser
pub fn syslog_rfc5424_transport_parser() -> TransportParser {
    TransportParser::new(
        "syslog_rfc5424_transport",
        "Syslog RFC5424 Transport",
        "Extracts RFC5424 syslog transport metadata with structured data support",
        parse_syslog_rfc5424_transport,
    )
}

/// Create File transport parser
pub fn file_transport_parser() -> TransportParser {
    TransportParser::new(
        "file_transport",
        "File Transport",
        "Handles file-based log ingestion with file metadata extraction",
        parse_file_transport,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::parser::transport::TransportResult;

    #[test]
    fn test_syslog_rfc3164_transport() {
        let log = "<34>Dec 25 10:00:00 hostname programname[1234]: Apache access log entry here";
        let source = Origin::Hostname("syslog-server".to_string());

        let result = parse_syslog_rfc3164_transport(log, source);

        match result {
            TransportResult::Success(raw_event) => {
                // Check that transport metadata was extracted
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.original_message")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    log
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.hostname")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "hostname"
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.process")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "programname"
                );

                // RFC3164 has no year, so the parser assumes the current UTC year.
                let year = time::OffsetDateTime::now_utc().year();
                let expected = time::PrimitiveDateTime::new(
                    time::Date::from_calendar_date(year, time::Month::December, 25).unwrap(),
                    time::Time::from_hms(10, 0, 0).unwrap(),
                )
                .assume_utc();
                assert_eq!(raw_event.original_time.as_secs(), expected.unix_timestamp());
            }
            _ => panic!("Expected successful transport parse"),
        }
    }

    #[test]
    fn test_file_transport() {
        let log = "127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] \"GET / HTTP/1.1\" 200 2326";
        let source = Origin::File("/var/log/apache2/access.log".to_string());

        let result = parse_file_transport(log, source);

        match result {
            TransportResult::Success(raw_event) => {
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.type")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "file"
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.file.name")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "access.log"
                );
            }
            _ => panic!("Expected successful file transport parse"),
        }
    }

    #[test]
    fn test_syslog_rfc5424_structured_data() {
        let log = r#"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application"][examplePriority@32473 class="high"] An application event log entry"#;
        let source = Origin::Hostname("syslog-server".to_string());

        let result = parse_syslog_rfc5424_transport(log, source);

        match result {
            TransportResult::Success(raw_event) => {
                // Check basic RFC5424 fields
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.version")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "1"
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.app_name")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "evntslog"
                );

                // Check structured data parsing - first element [exampleSDID@32473 iut="3" eventSource="Application"]
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.structured_data.exampleSDID@32473.sd_id")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "exampleSDID@32473"
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.structured_data.exampleSDID@32473.iut")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "3"
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.structured_data.exampleSDID@32473.eventSource")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "Application"
                );

                // Check structured data parsing - second element [examplePriority@32473 class="high"]
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.structured_data.examplePriority@32473.sd_id")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "examplePriority@32473"
                );
                assert_eq!(
                    raw_event
                        .fields
                        .get("transport.syslog.structured_data.examplePriority@32473.class")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "high"
                );

                // Verify raw structured data is also stored
                assert!(
                    raw_event
                        .fields
                        .contains_key("transport.syslog.structured_data_raw")
                );

                // Verify message body was extracted correctly
                assert_eq!(raw_event.log_text, "An application event log entry");

                // RFC5424 timestamps are RFC3339 and should be parsed exactly.
                assert_eq!(
                    raw_event.original_time,
                    Timestamp::from_rfc3339("2003-10-11T22:14:15.003Z").unwrap()
                );
            }
            _ => panic!("Expected successful transport parse"),
        }
    }
}
