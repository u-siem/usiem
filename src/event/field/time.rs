/// Specialized time field wrapping i64 nanoseconds since Unix epoch (UTC)
/// 
/// All timestamps in the SIEM system are stored and handled in UTC to ensure
/// consistent time handling across different systems, timezones, and log sources.
/// 
/// # UTC Guarantees
/// 
/// - **Storage**: Always nanoseconds since Unix epoch (1970-01-01T00:00:00Z)
/// - **Parsing**: Input with timezone offsets is converted to UTC
/// - **Output**: Always rendered in UTC unless explicitly converted
/// - **Arithmetic**: All operations preserve UTC semantics
/// 
/// # Design Rationale
/// 
/// SIEM systems must correlate events from multiple sources across different
/// timezones. By normalizing all timestamps to UTC, we ensure:
/// - Accurate event ordering and correlation
/// - Consistent time-based queries and analysis  
/// - No ambiguity during daylight saving time transitions
/// - Reliable forensic timeline reconstruction
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub i64);

#[derive(Debug, Clone)]
pub enum TimeParseError {
    InvalidFormat,
    OutOfRange,
    ParseError(String),
}

impl Timestamp {
    /// Create a new Timestamp from nanoseconds since Unix epoch
    pub fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    /// Create from milliseconds since Unix epoch
    pub fn from_millis(millis: i64) -> Self {
        Self(millis * 1_000_000)
    }

    /// Create from seconds since Unix epoch
    pub fn from_secs(secs: i64) -> Self {
        Self(secs * 1_000_000_000)
    }

    /// Get nanoseconds since Unix epoch
    pub fn as_nanos(&self) -> i64 {
        self.0
    }

    /// Get milliseconds since Unix epoch
    pub fn as_millis(&self) -> i64 {
        self.0 / 1_000_000
    }

    /// Get seconds since Unix epoch
    pub fn as_secs(&self) -> i64 {
        self.0 / 1_000_000_000
    }

    /// Create from current system time
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        Self(nanos)
    }

    /// Create from RFC3339 string (e.g., "2025-10-11T10:30:00Z")
    /// 
    /// Input timestamps with timezone offsets are automatically converted to UTC.
    /// Examples:
    /// - "2025-10-11T10:30:00Z" → UTC timestamp
    /// - "2025-10-11T10:30:00-05:00" → Converted to UTC (15:30:00Z)
    /// - "2025-10-11T10:30:00+02:00" → Converted to UTC (08:30:00Z)
    pub fn from_rfc3339(s: &str) -> Result<Self, TimeParseError> {
        use time::{OffsetDateTime, format_description::well_known::Rfc3339};

        let dt = OffsetDateTime::parse(s, &Rfc3339)
            .map_err(|e| TimeParseError::ParseError(e.to_string()))?;

        let nanos = dt.unix_timestamp_nanos();
        // Convert i128 to i64, checking for overflow
        let nanos_i64 = nanos.try_into().map_err(|_| TimeParseError::OutOfRange)?;

        Ok(Self(nanos_i64))
    }

    /// Convert to RFC3339 string in UTC timezone
    /// 
    /// Always outputs timestamps with 'Z' suffix indicating UTC.
    /// Example: "2025-10-11T10:30:00.123456789Z"
    pub fn to_rfc3339(&self) -> String {
        use time::{OffsetDateTime, format_description::well_known::Rfc3339};

        // Convert i64 nanoseconds to i128 for the time crate
        let nanos_i128 = self.0 as i128;

        // Convert nanoseconds to OffsetDateTime in UTC
        match OffsetDateTime::from_unix_timestamp_nanos(nanos_i128) {
            Ok(dt) => {
                // Ensure we're explicitly using UTC offset
                let utc_dt = dt.to_offset(time::UtcOffset::UTC);
                utc_dt
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| format!("Timestamp({})", self.0))
            }
            Err(_) => format!("Timestamp({})", self.0),
        }
    }

    /// Create from ISO 8601 string (alias for from_rfc3339)
    pub fn from_iso8601(s: &str) -> Result<Self, TimeParseError> {
        Self::from_rfc3339(s)
    }

    /// Convert to ISO 8601 string (alias for to_rfc3339)
    pub fn to_iso8601(&self) -> String {
        self.to_rfc3339()
    }

    /// Create from Unix timestamp (seconds) and nanoseconds
    pub fn from_unix_timestamp(secs: i64, nanos: u32) -> Self {
        Self(secs * 1_000_000_000 + nanos as i64)
    }

    /// Get Unix timestamp as (seconds, nanoseconds)
    pub fn as_unix_timestamp(&self) -> (i64, u32) {
        let secs = self.0 / 1_000_000_000;
        let nanos = (self.0 % 1_000_000_000) as u32;
        (secs, nanos)
    }

    /// Get microseconds since Unix epoch
    pub fn as_micros(&self) -> i64 {
        self.0 / 1_000
    }

    /// Create from microseconds since Unix epoch
    pub fn from_micros(micros: i64) -> Self {
        Self(micros * 1_000)
    }

    /// Add duration in nanoseconds
    pub fn add_nanos(self, nanos: i64) -> Self {
        Self(self.0.saturating_add(nanos))
    }

    /// Subtract duration in nanoseconds
    pub fn sub_nanos(self, nanos: i64) -> Self {
        Self(self.0.saturating_sub(nanos))
    }

    /// Add duration in seconds
    pub fn add_secs(self, secs: i64) -> Self {
        self.add_nanos(secs.saturating_mul(1_000_000_000))
    }

    /// Subtract duration in seconds
    pub fn sub_secs(self, secs: i64) -> Self {
        self.sub_nanos(secs.saturating_mul(1_000_000_000))
    }

    /// Check if this timestamp is before another
    pub fn is_before(&self, other: &Timestamp) -> bool {
        self.0 < other.0
    }

    /// Check if this timestamp is after another
    pub fn is_after(&self, other: &Timestamp) -> bool {
        self.0 > other.0
    }

    /// Calculate duration between two timestamps in nanoseconds
    pub fn duration_since(&self, earlier: &Timestamp) -> i64 {
        self.0 - earlier.0
    }

    /// Calculate elapsed time since this timestamp to now
    pub fn elapsed(&self) -> i64 {
        Self::now().0 - self.0
    }

    /// Get timestamp as Duration since Unix epoch
    pub fn as_duration_since_epoch(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.0 as u64)
    }

    /// Create from current system time (guaranteed UTC)
    pub fn utc_now() -> Self {
        Self::now() // already UTC, but explicit alias
    }

    /// Convert to RFC3339 string with explicit UTC timezone (alias for to_rfc3339)
    pub fn to_utc_rfc3339(&self) -> String {
        self.to_rfc3339()
    }

    /// Get human readable UTC string for debugging
    pub fn to_utc_string(&self) -> String {
        use time::{OffsetDateTime, UtcOffset, format_description};

        let nanos_i128 = self.0 as i128;
        match OffsetDateTime::from_unix_timestamp_nanos(nanos_i128) {
            Ok(dt) => {
                let utc_dt = dt.to_offset(UtcOffset::UTC);
                if let Ok(format) = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC") {
                    utc_dt.format(&format)
                        .unwrap_or_else(|_| format!("Timestamp({}ns)", self.0))
                } else {
                    self.to_rfc3339() // fallback
                }
            }
            Err(_) => format!("Timestamp({}ns)", self.0),
        }
    }

    /// Validate that timestamp is reasonable for SIEM use (not too far in past/future)
    pub fn is_reasonable_siem_timestamp(&self) -> bool {
        // Reasonable range: 1970-01-01 to ~2100-01-01
        // This catches obvious errors like microsecond timestamps being used as nanoseconds
        let min_reasonable = 0; // 1970-01-01T00:00:00Z
        let max_reasonable = 4_102_444_800_000_000_000i64; // ~2100-01-01T00:00:00Z in nanos
        
        self.0 >= min_reasonable && self.0 <= max_reasonable
    }
}

impl std::fmt::Display for TimeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeParseError::InvalidFormat => write!(f, "Invalid time format"),
            TimeParseError::OutOfRange => write!(f, "Time value out of range"),
            TimeParseError::ParseError(msg) => write!(f, "Time parse error: {}", msg),
        }
    }
}

impl std::error::Error for TimeParseError {}

impl std::ops::Add<i64> for Timestamp {
    type Output = Timestamp;

    fn add(self, nanos: i64) -> Self::Output {
        self.add_nanos(nanos)
    }
}

impl std::ops::Sub<i64> for Timestamp {
    type Output = Timestamp;

    fn sub(self, nanos: i64) -> Self::Output {
        self.sub_nanos(nanos)
    }
}

impl std::ops::Sub<Timestamp> for Timestamp {
    type Output = i64;

    fn sub(self, other: Timestamp) -> Self::Output {
        self.duration_since(&other)
    }
}

impl From<i64> for Timestamp {
    fn from(nanos: i64) -> Self {
        Self::from_nanos(nanos)
    }
}

impl From<Timestamp> for i64 {
    fn from(ts: Timestamp) -> Self {
        ts.as_nanos()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Time({}ns)", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_parsing() {
        // Test parsing a standard RFC3339 timestamp
        let timestamp_str = "2025-10-11T10:30:00Z";
        let timestamp = Timestamp::from_rfc3339(timestamp_str).expect("Should parse RFC3339");

        // Test that we can convert back to RFC3339
        let converted_back = timestamp.to_rfc3339();
        assert!(converted_back.contains("2025-10-11"));
        assert!(converted_back.contains("10:30:00"));
    }

    #[test]
    fn test_rfc3339_with_offset() {
        // Test parsing RFC3339 with timezone offset
        let timestamp_str = "2025-10-11T10:30:00-05:00";
        let timestamp =
            Timestamp::from_rfc3339(timestamp_str).expect("Should parse RFC3339 with offset");

        // Convert back and verify it's valid
        let converted_back = timestamp.to_rfc3339();
        assert!(!converted_back.is_empty());
    }

    #[test]
    fn test_rfc3339_with_nanoseconds() {
        // Test parsing RFC3339 with fractional seconds
        let timestamp_str = "2025-10-11T10:30:00.123456789Z";
        let timestamp =
            Timestamp::from_rfc3339(timestamp_str).expect("Should parse RFC3339 with nanoseconds");

        // Verify nanosecond precision is maintained
        assert!(timestamp.as_nanos() % 1_000_000_000 != 0);
    }

    #[test]
    fn test_invalid_rfc3339() {
        // Test that invalid formats return errors
        let invalid_cases = [
            "not-a-timestamp",
            "2025-13-11T10:30:00Z", // Invalid month
            "2025-10-32T10:30:00Z", // Invalid day
            "2025-10-11T25:30:00Z", // Invalid hour
        ];

        for case in &invalid_cases {
            assert!(
                Timestamp::from_rfc3339(case).is_err(),
                "Should reject invalid format: {}",
                case
            );
        }
    }

    #[test]
    fn test_timestamp_arithmetic() {
        let ts1 = Timestamp::from_secs(1000);
        let ts2 = ts1 + 500_000_000; // Add 0.5 seconds in nanoseconds

        assert_eq!(ts2.as_secs(), 1000);
        assert_eq!(ts2.as_nanos(), 1000_500_000_000);

        let duration = ts2 - ts1;
        assert_eq!(duration, 500_000_000);
    }

    #[test]
    fn test_timestamp_comparison() {
        let ts1 = Timestamp::from_secs(1000);
        let ts2 = Timestamp::from_secs(2000);

        assert!(ts1.is_before(&ts2));
        assert!(ts2.is_after(&ts1));
        assert!(!ts1.is_after(&ts2));
        assert!(!ts2.is_before(&ts1));
    }

    #[test]
    fn test_unix_timestamp_conversion() {
        let (secs, nanos) = (1640995200, 123456789); // 2022-01-01 00:00:00.123456789 UTC
        let ts = Timestamp::from_unix_timestamp(secs, nanos);

        let (converted_secs, converted_nanos) = ts.as_unix_timestamp();
        assert_eq!(converted_secs, secs);
        assert_eq!(converted_nanos, nanos);
    }

    #[test]
    fn test_utc_timezone_handling() {
        // Test that timezone offsets are properly converted to UTC
        let test_cases = [
            "2025-10-11T10:30:00Z",     // Already UTC
            "2025-10-11T10:30:00+00:00", // +00:00 = UTC
        ];

        for input in &test_cases {
            let ts = Timestamp::from_rfc3339(input).expect("Should parse");
            let output = ts.to_rfc3339();
            
            // Verify it's in UTC (ends with Z)
            assert!(output.ends_with('Z'), "Output should end with Z: {}", output);
            
            // Verify it contains the expected time components
            assert!(output.contains("2025-10-11"), "Should contain date");
            assert!(output.contains("10:30:00"), "Should contain time");
        }
    }

    #[test]
    fn test_timezone_offset_conversion() {
        // Test conversion of timezone offsets to UTC
        let cases = [
            ("2025-10-11T15:30:00-05:00", 20, 30), // EST: 15:30-05:00 = 20:30 UTC
            ("2025-10-11T08:30:00+02:00", 6, 30),  // CET: 08:30+02:00 = 06:30 UTC
        ];

        for (input, expected_hour, expected_minute) in &cases {
            let ts = Timestamp::from_rfc3339(input).expect("Should parse timezone offset");
            let output = ts.to_rfc3339();
            
            // Verify conversion to UTC
            assert!(output.ends_with('Z'), "Should convert to UTC");
            
            let time_part = format!("{:02}:{:02}", expected_hour, expected_minute);
            assert!(output.contains(&time_part), 
                "Expected {} to contain {}, got {}", input, time_part, output);
        }
    }

    #[test]
    fn test_utc_helper_methods() {
        let ts = Timestamp::utc_now();
        
        // Test UTC string formatting
        let utc_str = ts.to_utc_string();
        assert!(utc_str.contains("UTC") || utc_str.starts_with("Timestamp("));
        
        // Test UTC RFC3339 alias
        let rfc3339_1 = ts.to_rfc3339();
        let rfc3339_2 = ts.to_utc_rfc3339();
        assert_eq!(rfc3339_1, rfc3339_2);
    }

    #[test]
    fn test_reasonable_siem_timestamp() {
        // Reasonable timestamps
        let reasonable_cases = [
            Timestamp::from_secs(1640995200), // 2022-01-01
            Timestamp::from_secs(1893456000), // 2030-01-01
            Timestamp::utc_now(),
        ];
        
        for ts in &reasonable_cases {
            assert!(ts.is_reasonable_siem_timestamp(), 
                "Should be reasonable: {}", ts.as_secs());
        }
        
        // Unreasonable timestamps  
        let unreasonable_cases = [
            Timestamp::from_secs(5000000000),      // Year ~2128 = too far future  
            Timestamp::from_nanos(-1),             // Before epoch
        ];
        
        for (i, ts) in unreasonable_cases.iter().enumerate() {
            assert!(!ts.is_reasonable_siem_timestamp(),
                "Case {}: Should be unreasonable: {} seconds = {} nanos", 
                i, ts.as_secs(), ts.as_nanos());
        }
    }
}
