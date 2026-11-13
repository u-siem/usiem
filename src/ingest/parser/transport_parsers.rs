use crate::event::field::Timestamp;
use crate::event::{Origin, RawEvent};
use crate::ingest::parser::transport::{TransportParser, TransportResult};
use regex::Regex;
use std::sync::LazyLock;

// Syslog transport parsers for RFC3164 and RFC5424, and the ISO-8601
// format rsyslog writes to files.

// Static regex for RFC3164 syslog format. `<PRI>` is optional: log files
// (and some senders) write the header without it. The body may span lines
// (a multiline record from a file).
static SYSLOG_RFC3164_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Single-digit days are space-padded ("Nov  4") by most senders.
    Regex::new(
        r#"^(?:<(\d{1,3})>)?(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:\[]+)(?:\[(\d+)\])?: ((?s:.*))$"#,
    )
    .expect("Invalid Syslog RFC3164 regex")
});

// RFC3164 without a HOSTNAME (`Nov 12 10:00:00 dnsmasq[9]: query...`, as
// Pi-hole and BSD syslogd write). Tried first: a token ending in `:` (or
// `[pid]:`) right after the time is a tag, never a host name.
static SYSLOG_RFC3164_HOSTLESS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(?:<(\d{1,3})>)?(\w{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}) ([^\s:\[]+)(?:\[(\d+)\])?: ((?s:.*))$"#,
    )
    .expect("Invalid hostless Syslog RFC3164 regex")
});

// rsyslog's file format (`RSYSLOG_FileFormat`, the Debian default since
// bookworm): an RFC 3339 time with an offset, then the RFC 3164 fields.
static SYSLOG_FILE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) (\S+) ([^:\[]+)(?:\[(\d+)\])?: ((?s:.*))$"#,
    )
    .expect("Invalid syslog file-format regex")
});

// Static regex for RFC5424 syslog format
static SYSLOG_RFC5424_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // STRUCTURED-DATA is "-" or one or more [elements]; MSG is optional.
    Regex::new(r#"^<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+)(?: ((?s:.*)))?$"#)
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

/// Turns the local wall-clock time of an RFC 3164 header into UTC.
///
/// RFC 3164 times carry no zone. [`time::UtcOffset`] implements this for a
/// fixed offset; an application with a time-zone database can implement it
/// to follow daylight saving time.
pub trait LocalTime: Send + Sync {
    /// `None` when the time does not exist in this zone.
    fn to_utc(&self, local: time::PrimitiveDateTime) -> Option<time::OffsetDateTime>;
}

impl LocalTime for time::UtcOffset {
    fn to_utc(&self, local: time::PrimitiveDateTime) -> Option<time::OffsetDateTime> {
        Some(local.assume_offset(*self))
    }
}

/// How [`parse_syslog_rfc3164_transport_with`] reads header times.
#[derive(Clone, Copy)]
pub struct Rfc3164Options<'a> {
    /// The sender's time zone.
    pub zone: &'a dyn LocalTime,
    /// The reference "now" for the missing year: a time more than a day
    /// after it belongs to the previous year (a December line read in
    /// January).
    pub now: Timestamp,
}

impl Rfc3164Options<'static> {
    /// UTC, with the current time as reference.
    pub fn utc() -> Self {
        Rfc3164Options {
            zone: &time::UtcOffset::UTC,
            now: Timestamp::now(),
        }
    }
}

const DAY_NANOS: i64 = 86_400 * 1_000_000_000;

/// RFC3164 timestamps omit the year (e.g. "Dec 25 10:00:00") and carry no
/// timezone: the time is read in `options.zone`, in the year of
/// `options.now`, or the year before when that would put it more than a day
/// in the future.
fn parse_rfc3164_timestamp(raw: &str, options: &Rfc3164Options<'_>) -> Option<Timestamp> {
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
    let time_of_day = time::Time::from_hms(hour, minute, second).ok()?;

    let now = options.now.as_nanos();
    let year = time::OffsetDateTime::from_unix_timestamp_nanos(now as i128)
        .ok()?
        .year();
    let at = |year: i32| -> Option<i64> {
        // Feb 29 does not exist in every year.
        let date = time::Date::from_calendar_date(year, month, day).ok()?;
        let utc = options
            .zone
            .to_utc(time::PrimitiveDateTime::new(date, time_of_day))?;
        utc.unix_timestamp_nanos().try_into().ok()
    };
    let nanos = match at(year) {
        Some(n) if n <= now.saturating_add(DAY_NANOS) => n,
        _ => at(year - 1)?,
    };
    Some(Timestamp::from_nanos(nanos))
}

/// Syslog RFC3164 transport parser
/// Extracts syslog transport metadata and isolates message body for content parsing
/// Example: <34>Dec 25 10:00:00 hostname programname[1234]: This is a message
///
/// The `<PRI>` and the HOSTNAME may be missing (log files, Pi-hole). Times
/// are read as UTC; [`parse_syslog_rfc3164_transport_with`] takes a zone.
pub fn parse_syslog_rfc3164_transport(log_text: &str, source: Origin) -> TransportResult {
    parse_syslog_rfc3164_transport_with(log_text, source, &Rfc3164Options::utc())
}

/// [`parse_syslog_rfc3164_transport`] with the sender's time zone and the
/// reference time for the missing year.
pub fn parse_syslog_rfc3164_transport_with(
    log_text: &str,
    source: Origin,
    options: &Rfc3164Options<'_>,
) -> TransportResult {
    // (priority, timestamp, hostname, program, pid, body)
    let parts = if let Some(c) = SYSLOG_RFC3164_HOSTLESS_REGEX.captures(log_text) {
        (
            c.get(1).map(|m| m.as_str()),
            c.get(2).unwrap().as_str(),
            None,
            c.get(3).unwrap().as_str(),
            c.get(4).map(|m| m.as_str()),
            c.get(5).unwrap().as_str(),
        )
    } else if let Some(c) = SYSLOG_RFC3164_REGEX.captures(log_text) {
        (
            c.get(1).map(|m| m.as_str()),
            c.get(2).unwrap().as_str(),
            Some(c.get(3).unwrap().as_str()),
            c.get(4).unwrap().as_str(),
            c.get(5).map(|m| m.as_str()),
            c.get(6).unwrap().as_str(),
        )
    } else {
        // Not syslog RFC3164 format - return origin for next parser to try
        return TransportResult::NoMatch(source);
    };
    let (priority, timestamp_str, hostname, process_name, pid, message_body) = parts;

    // Create RawEvent with the message body for content parsing.
    // `timestamp` (arrival time) is ingest time; `original_time` becomes
    // the syslog header's own timestamp when it parses successfully.
    let mut raw_event = RawEvent::new(
        message_body.to_string(), // Body goes to log_text for content parsing
        Timestamp::now(),
        source,
    );
    if let Some(ts) = parse_rfc3164_timestamp(timestamp_str, options) {
        raw_event.original_time = ts;
    }

    // Store transport metadata in fields
    if let Some(priority) = priority.and_then(|p| p.parse::<u32>().ok()) {
        insert_priority(&mut raw_event, priority);
    }

    raw_event.insert_field("transport.syslog.version", "rfc3164".to_string());
    raw_event.insert_field("transport.syslog.timestamp", timestamp_str.to_string());
    insert_tag(&mut raw_event, hostname, process_name, pid);

    // Store original syslog message for reference
    raw_event.insert_field("transport.original_message", log_text.to_string());

    TransportResult::Success(raw_event)
}

/// rsyslog's file format: `2026-11-12T10:00:00.123456+01:00 host prog[pid]: msg`
/// (`RSYSLOG_FileFormat`). Fills the same fields as the RFC 3164 parser,
/// with `transport.syslog.version` = `rfc3339`, so content parsers keyed on
/// the program name work unchanged.
pub fn parse_syslog_file_transport(log_text: &str, source: Origin) -> TransportResult {
    let Some(c) = SYSLOG_FILE_REGEX.captures(log_text) else {
        return TransportResult::NoMatch(source);
    };
    let timestamp_str = c.get(1).unwrap().as_str();
    let mut raw_event = RawEvent::new(
        c.get(5).unwrap().as_str().to_string(),
        Timestamp::now(),
        source,
    );
    if let Ok(ts) = Timestamp::from_rfc3339(timestamp_str) {
        raw_event.original_time = ts;
    }
    raw_event.insert_field("transport.syslog.version", "rfc3339".to_string());
    raw_event.insert_field("transport.syslog.timestamp", timestamp_str.to_string());
    insert_tag(
        &mut raw_event,
        Some(c.get(2).unwrap().as_str()),
        c.get(3).unwrap().as_str(),
        c.get(4).map(|m| m.as_str()),
    );
    raw_event.insert_field("transport.original_message", log_text.to_string());
    TransportResult::Success(raw_event)
}

fn insert_priority(raw_event: &mut RawEvent, priority: u32) {
    raw_event.insert_field("transport.syslog.priority", priority as i64);
    raw_event.insert_field("transport.syslog.facility", (priority / 8) as i64);
    raw_event.insert_field("transport.syslog.severity", (priority % 8) as i64);
}

fn insert_tag(raw_event: &mut RawEvent, hostname: Option<&str>, process: &str, pid: Option<&str>) {
    if let Some(hostname) = hostname {
        raw_event.insert_field("transport.syslog.hostname", hostname.to_string());
    }
    raw_event.insert_field("transport.syslog.process", process.to_string());
    if let Some(pid) = pid.and_then(|p| p.parse::<i64>().ok()) {
        raw_event.insert_field("transport.syslog.pid", pid);
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
        let message_body = captures.get(9).map_or("", |m| m.as_str());

        // Create RawEvent with message body for content parsing.
        // `timestamp` (arrival time) is ingest time; `original_time` becomes
        // the syslog header's own RFC3339 timestamp when it parses successfully.
        let mut raw_event = RawEvent::new(message_body.to_string(), Timestamp::now(), source);
        if let Ok(ts) = Timestamp::from_rfc3339(timestamp_str) {
            raw_event.original_time = ts;
        }

        // Store RFC5424 transport metadata
        if let Ok(priority) = priority_str.parse::<u32>() {
            insert_priority(&mut raw_event, priority);
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

/// Create the rsyslog file-format transport parser
pub fn syslog_file_transport_parser() -> TransportParser {
    TransportParser::new(
        "syslog_file_transport",
        "Syslog File Format Transport",
        "Parses rsyslog's file format: an RFC 3339 time, host and tag",
        parse_syslog_file_transport,
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

                // RFC3164 has no year: the current UTC year, or the previous
                // one while Dec 25 is still more than a day away.
                let now = time::OffsetDateTime::now_utc();
                let in_year = |year| {
                    time::PrimitiveDateTime::new(
                        time::Date::from_calendar_date(year, time::Month::December, 25).unwrap(),
                        time::Time::from_hms(10, 0, 0).unwrap(),
                    )
                    .assume_utc()
                };
                let mut expected = in_year(now.year());
                if expected > now + time::Duration::DAY {
                    expected = in_year(now.year() - 1);
                }
                assert_eq!(raw_event.original_time.as_secs(), expected.unix_timestamp());
            }
            _ => panic!("Expected successful transport parse"),
        }
    }

    #[test]
    fn rfc3164_accepts_space_padded_day() {
        let log = "<13>Nov  4 09:05:01 nas CRON[812]: (root) CMD (run-parts)";
        let TransportResult::Success(raw) =
            parse_syslog_rfc3164_transport(log, Origin::Hostname("t".into()))
        else {
            panic!("padded day should match");
        };
        assert_eq!(raw.log_text, "(root) CMD (run-parts)");
        assert_eq!(
            raw.fields.get("transport.syslog.process").unwrap().as_str(),
            Some("CRON")
        );
    }

    #[test]
    fn rfc5424_without_structured_data_or_message() {
        let log = "<34>1 2024-05-01T10:00:00Z host app 42 ID7 - 'su root' failed";
        let TransportResult::Success(raw) =
            parse_syslog_rfc5424_transport(log, Origin::Hostname("t".into()))
        else {
            panic!("nil structured data should match");
        };
        assert_eq!(raw.log_text, "'su root' failed");
        assert!(
            !raw.fields
                .contains_key("transport.syslog.structured_data_raw")
        );

        let bare = "<34>1 2024-05-01T10:00:00Z host app - - -";
        let TransportResult::Success(raw) =
            parse_syslog_rfc5424_transport(bare, Origin::Hostname("t".into()))
        else {
            panic!("a message-less frame should match");
        };
        assert_eq!(raw.log_text, "");
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

    fn field<'a>(raw: &'a RawEvent, name: &str) -> Option<&'a str> {
        raw.fields.get(name).and_then(|v| v.as_str())
    }

    fn at(rfc3339: &str) -> Timestamp {
        Timestamp::from_rfc3339(rfc3339).unwrap()
    }

    #[test]
    fn rfc3164_without_pri_as_written_to_files() {
        let log = "Nov  4 09:05:01 nas sshd[812]: Accepted publickey for bob";
        let TransportResult::Success(raw) =
            parse_syslog_rfc3164_transport(log, Origin::Hostname("t".into()))
        else {
            panic!("a header without <PRI> should match");
        };
        assert_eq!(field(&raw, "transport.syslog.hostname"), Some("nas"));
        assert_eq!(field(&raw, "transport.syslog.process"), Some("sshd"));
        assert!(!raw.fields.contains_key("transport.syslog.priority"));
        assert_eq!(raw.log_text, "Accepted publickey for bob");
    }

    #[test]
    fn rfc3164_without_hostname() {
        let log = "Nov 12 10:00:00 dnsmasq[912]: query[A] example.com from 10.0.0.5";
        let TransportResult::Success(raw) =
            parse_syslog_rfc3164_transport(log, Origin::Hostname("t".into()))
        else {
            panic!("a hostless header should match");
        };
        assert_eq!(field(&raw, "transport.syslog.process"), Some("dnsmasq"));
        assert!(!raw.fields.contains_key("transport.syslog.hostname"));
        assert_eq!(raw.log_text, "query[A] example.com from 10.0.0.5");

        // A host followed by a tag is still a host.
        let log = "<12>Nov  4 09:05:01 gw kernel: [UFW BLOCK] IN=eth0";
        let TransportResult::Success(raw) =
            parse_syslog_rfc3164_transport(log, Origin::Hostname("t".into()))
        else {
            panic!();
        };
        assert_eq!(field(&raw, "transport.syslog.hostname"), Some("gw"));
        assert_eq!(field(&raw, "transport.syslog.process"), Some("kernel"));
    }

    #[test]
    fn rfc3164_body_may_span_lines() {
        let log = "Nov  4 09:05:01 app java[1]: boom\n\tat a.b(C.java:1)";
        let TransportResult::Success(raw) =
            parse_syslog_rfc3164_transport(log, Origin::Hostname("t".into()))
        else {
            panic!("a multiline record should match");
        };
        assert_eq!(raw.log_text, "boom\n\tat a.b(C.java:1)");
    }

    #[test]
    fn rfc3164_times_follow_the_zone_and_infer_the_year() {
        let plus_one = time::UtcOffset::from_hms(1, 0, 0).unwrap();
        let options = Rfc3164Options {
            zone: &plus_one,
            now: at("2026-06-01T00:00:00Z"),
        };
        let TransportResult::Success(raw) = parse_syslog_rfc3164_transport_with(
            "<13>Mar  3 10:00:00 h p: x",
            Origin::Hostname("t".into()),
            &options,
        ) else {
            panic!();
        };
        assert_eq!(raw.original_time, at("2026-03-03T09:00:00Z"));

        // Read in January, a December line is last year's.
        let options = Rfc3164Options {
            zone: &time::UtcOffset::UTC,
            now: at("2027-01-02T00:00:00Z"),
        };
        let TransportResult::Success(raw) = parse_syslog_rfc3164_transport_with(
            "Dec 31 23:59:59 h p: x",
            Origin::Hostname("t".into()),
            &options,
        ) else {
            panic!();
        };
        assert_eq!(raw.original_time, at("2026-12-31T23:59:59Z"));
        // Up to a day ahead (clock skew) stays in this year.
        let TransportResult::Success(raw) = parse_syslog_rfc3164_transport_with(
            "Jan  2 12:00:00 h p: x",
            Origin::Hostname("t".into()),
            &options,
        ) else {
            panic!();
        };
        assert_eq!(raw.original_time, at("2027-01-02T12:00:00Z"));
    }

    #[test]
    fn rsyslog_file_format() {
        let log = "2026-11-12T10:00:00.123456+01:00 nas sshd[812]: Failed password for root";
        let TransportResult::Success(raw) =
            parse_syslog_file_transport(log, Origin::Hostname("t".into()))
        else {
            panic!("the rsyslog file format should match");
        };
        assert_eq!(field(&raw, "transport.syslog.version"), Some("rfc3339"));
        assert_eq!(field(&raw, "transport.syslog.hostname"), Some("nas"));
        assert_eq!(field(&raw, "transport.syslog.process"), Some("sshd"));
        assert_eq!(
            raw.fields
                .get("transport.syslog.pid")
                .and_then(|v| v.as_i64()),
            Some(812)
        );
        assert_eq!(raw.log_text, "Failed password for root");
        assert_eq!(raw.original_time, at("2026-11-12T09:00:00.123456Z"));

        assert!(matches!(
            parse_syslog_file_transport("<13>Nov  4 09:05:01 h p: x", Origin::Hostname("t".into())),
            TransportResult::NoMatch(_)
        ));
    }
}
