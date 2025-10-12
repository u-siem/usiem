use crate::event::field::{FieldValue, Timestamp};
use crate::event::json::JsonValue;
use crate::event::origin::Origin;
use std::collections::HashMap;

/// Represents the raw event data in its original form
#[derive(Debug, Clone, PartialEq)]
pub enum RawData {
    /// Raw text/string log entry
    Text(String),
    /// Structured JSON data (from ES bulk collectors, etc.)
    Json(JsonValue),
}

/// Core immutable event structure containing the original event data
/// This structure is Send + Sync for multi-threaded processing pipelines
#[derive(Debug, Clone)]
pub struct Event {
    /// When this event arrived at our SIEM system
    pub(crate) arrival_time: Timestamp,

    /// When the event was originally created (from the source system)
    pub(crate) original_time: Timestamp,

    /// The origin/source of this event
    pub(crate) origin: Origin,

    /// The raw event data in its original form (immutable)
    pub(crate) raw_data: RawData,

    /// Parsed field data extracted from the raw event
    pub(crate) fields: HashMap<String, FieldValue>,
}

impl Event {
    /// Create a new event with the specified parameters
    pub fn new(
        arrival_time: Timestamp,
        original_time: Timestamp,
        origin: Origin,
        raw_data: RawData,
    ) -> Self {
        Self {
            arrival_time,
            original_time,
            origin,
            raw_data,
            fields: HashMap::new(),
        }
    }

    /// Get the arrival time of this event
    pub fn arrival_time(&self) -> Timestamp {
        self.arrival_time
    }

    /// Get the original creation time of this event
    pub fn original_time(&self) -> Timestamp {
        self.original_time
    }

    /// Get the origin/source of this event
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Get the raw event data (immutable reference)
    pub fn raw_data(&self) -> &RawData {
        &self.raw_data
    }

    /// Get the parsed field data
    pub fn fields(&self) -> &HashMap<String, FieldValue> {
        &self.fields
    }

    /// Add a parsed field to this event
    /// Note: This is for initial parsing only, not for transformations
    pub fn add_field(&mut self, key: String, value: FieldValue) {
        self.fields.insert(key, value);
    }

    /// Get a specific field value by key
    pub fn get_field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.get(key)
    }
}

// Ensure Event is Send + Sync for multi-threaded processing
unsafe impl Send for Event {}
unsafe impl Sync for Event {}

impl RawData {
    /// Create RawData from a text string
    pub fn from_text<S: Into<String>>(text: S) -> Self {
        RawData::Text(text.into())
    }

    /// Create RawData from JSON value
    pub fn from_json(json: JsonValue) -> Self {
        RawData::Json(json)
    }

    /// Get the raw data as a string representation
    pub fn as_string(&self) -> String {
        match self {
            RawData::Text(text) => text.clone(),
            RawData::Json(json) => json.to_string(),
        }
    }

    /// Check if this is text data
    pub fn is_text(&self) -> bool {
        matches!(self, RawData::Text(_))
    }

    /// Check if this is JSON data
    pub fn is_json(&self) -> bool {
        matches!(self, RawData::Json(_))
    }

    /// Get the text data if it's text, None otherwise
    pub fn as_text(&self) -> Option<&str> {
        match self {
            RawData::Text(text) => Some(text),
            RawData::Json(_) => None,
        }
    }

    /// Get the JSON data if it's JSON, None otherwise
    pub fn as_json(&self) -> Option<&JsonValue> {
        match self {
            RawData::Text(_) => None,
            RawData::Json(json) => Some(json),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::Ip;

    #[cfg(feature = "serde")]
    use serde_json;

    #[cfg(feature = "json")]
    use serde_json as external_json;

    #[test]
    fn test_event_creation() {
        let arrival_time = Timestamp::now();
        let original_time = Timestamp::now();
        let origin = Origin::from_hostname("test-server");
        let raw_data = RawData::from_text("test log entry");

        let event = Event::new(arrival_time, original_time, origin.clone(), raw_data);

        assert_eq!(event.arrival_time(), arrival_time);
        assert_eq!(event.original_time(), original_time);
        assert_eq!(event.origin(), &origin);
        assert!(event.raw_data().is_text());
    }

    #[test]
    fn test_origin_types() {
        use std::net::Ipv4Addr;

        let ip_origin = Origin::from_ip(Ip::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let hostname_origin = Origin::from_hostname("server.example.com");
        let collector_origin = Origin::from_collector("edr-agent-001");

        assert!(matches!(ip_origin, Origin::Ip(_)));
        assert!(matches!(hostname_origin, Origin::Hostname(_)));
        assert!(matches!(collector_origin, Origin::Collector(_)));

        assert_eq!(hostname_origin.as_string_ref(), Some("server.example.com"));
        assert_eq!(collector_origin.as_string_ref(), Some("edr-agent-001"));
        assert_eq!(ip_origin.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_raw_data_types() {
        use crate::event::json::JsonValue;

        let text_data = RawData::from_text("Sample log line");
        let json_data = RawData::from_json(JsonValue::object(vec![
            ("key", JsonValue::string("value")),
            ("number", JsonValue::number(42)),
        ]));

        assert!(text_data.is_text());
        assert!(!text_data.is_json());
        assert_eq!(text_data.as_text(), Some("Sample log line"));

        assert!(json_data.is_json());
        assert!(!json_data.is_text());
        assert!(json_data.as_json().is_some());
    }

    #[test]
    fn test_event_fields() {
        let mut event = Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_collector("test-collector"),
            RawData::from_text("test log"),
        );

        event.add_field("event_type".to_string(), FieldValue::str("security"));
        event.add_field("severity".to_string(), FieldValue::Int(3));

        assert_eq!(
            event.get_field("event_type"),
            Some(&FieldValue::str("security"))
        );
        assert_eq!(event.get_field("severity"), Some(&FieldValue::Int(3)));
        assert_eq!(event.get_field("nonexistent"), None);
    }

    #[test]
    fn test_event_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Event>();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_origin_serde() {
        use std::net::Ipv4Addr;

        let ip_origin = Origin::from_ip(Ip::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let hostname_origin = Origin::from_hostname("test-server");
        let collector_origin = Origin::from_collector("test-collector");

        // Test serialization
        let ip_json = serde_json::to_string(&ip_origin).unwrap();
        let hostname_json = serde_json::to_string(&hostname_origin).unwrap();
        let collector_json = serde_json::to_string(&collector_origin).unwrap();

        // Test deserialization
        let ip_deserialized: Origin = serde_json::from_str(&ip_json).unwrap();
        let hostname_deserialized: Origin = serde_json::from_str(&hostname_json).unwrap();
        let collector_deserialized: Origin = serde_json::from_str(&collector_json).unwrap();

        assert_eq!(ip_origin, ip_deserialized);
        assert_eq!(hostname_origin, hostname_deserialized);
        assert_eq!(collector_origin, collector_deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_raw_data_serde() {
        let text_data = RawData::from_text("test log");
        let json_data =
            RawData::from_json(JsonValue::object(vec![("key", JsonValue::string("value"))]));

        // Test serialization
        let text_json = serde_json::to_string(&text_data).unwrap();
        let json_json = serde_json::to_string(&json_data).unwrap();

        // Test deserialization
        let text_deserialized: RawData = serde_json::from_str(&text_json).unwrap();
        let json_deserialized: RawData = serde_json::from_str(&json_json).unwrap();

        assert_eq!(text_data, text_deserialized);
        assert_eq!(json_data, json_deserialized);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_serde_json_interop() {
        // Create a serde_json::Value
        let serde_value = external_json::json!({
            "name": "test",
            "count": 42,
            "active": true,
            "data": [1, 2, 3],
            "metadata": {
                "version": "1.0",
                "debug": false
            }
        });

        // Convert to our JsonValue
        let our_value = JsonValue::from(serde_value.clone());

        // Convert back to serde_json::Value
        let back_to_serde = external_json::Value::from(our_value);

        // Should be equal
        assert_eq!(serde_value, back_to_serde);
    }

    #[cfg(all(feature = "serde", feature = "json"))]
    #[test]
    fn test_full_event_serde_json_roundtrip() {
        use std::net::Ipv4Addr;

        // Create an event with JSON data from serde_json
        let serde_data = external_json::json!({
            "event_type": "authentication",
            "user": {"id": 123, "name": "admin"},
            "success": true
        });

        let event = Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_ip(Ip::V4(Ipv4Addr::new(10, 0, 0, 1))),
            RawData::from_json(JsonValue::from(serde_data)),
        );

        // Serialize the entire event
        let serialized = serde_json::to_string(&event).unwrap();

        // Deserialize it back
        let deserialized: Event = serde_json::from_str(&serialized).unwrap();

        // Verify the data is preserved
        assert_eq!(event.origin(), deserialized.origin());
        assert_eq!(event.raw_data(), deserialized.raw_data());
    }
}
