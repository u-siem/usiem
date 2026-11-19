use crate::event::field::{FieldValue, Timestamp};
use crate::event::fields;
use crate::event::hash::StableHasher;
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
#[derive(Debug, Clone, PartialEq)]
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

    /// Makes room for `additional` more fields, so a stage adding several
    /// (enrichment) rehashes once instead of on every insert.
    pub fn reserve_fields(&mut self, additional: usize) {
        self.fields.reserve(additional);
    }

    /// Get a specific field value by key
    pub fn get_field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.get(key)
    }

    /// A stable identifier for this event, suitable for deduplication.
    ///
    /// Derived from [`Event::origin`], [`Event::original_time`], and the raw
    /// content — deliberately *not* [`Event::arrival_time`] or the parsed
    /// fields, so that a re-delivered duplicate of the same source event
    /// (different arrival time, same origin/original_time/content) produces
    /// the same [`EventId`], and enrichment never changes it. This is a
    /// content hash, not a random globally-unique identifier: two genuinely
    /// distinct events that share origin, original_time, and raw content
    /// will collide.
    ///
    /// The value is fixed across builds and Rust releases (see
    /// [`crate::event::hash`]), so it may be stored. For an event read back
    /// from storage, prefer [`Event::stored_or_computed_id`]: data written by
    /// older versions may carry an id this function no longer computes.
    pub fn id(&self) -> EventId {
        let mut hasher = StableHasher::new();
        hasher.write_origin(&self.origin);
        hasher.write_timestamp(self.original_time);
        match &self.raw_data {
            RawData::Text(text) => {
                hasher.write_u8(0);
                hasher.write_str(text);
            }
            RawData::Json(json) => {
                hasher.write_u8(1);
                hasher.write_str(&json.to_string());
            }
        }
        EventId(hasher.finish())
    }

    /// The id stored in the [`fields::EVENT_ID`] field, when it is present
    /// and in the 16-hex-digit form [`EventId`]'s `Display` writes.
    pub fn recorded_id(&self) -> Option<EventId> {
        self.get_field(fields::EVENT_ID)?.as_str()?.parse().ok()
    }

    /// [`Event::recorded_id`] when present, otherwise [`Event::id`]: the id
    /// to use for an event read back from storage, so links written when it
    /// was stored keep resolving.
    pub fn stored_or_computed_id(&self) -> EventId {
        self.recorded_id().unwrap_or_else(|| self.id())
    }
}

/// A stable identifier for an [`Event`], returned by [`Event::id`].
///
/// See [`Event::id`] for what this is derived from and its collision
/// characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventId(u64);

impl EventId {
    /// The identifier as a raw `u64`.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// An id read back from storage (e.g. a stored `event.id` field), as
    /// [`EventId::as_u64`] gave it. It names the event it was computed
    /// from; nothing checks that such an event exists.
    pub fn from_u64(raw: u64) -> Self {
        EventId(raw)
    }
}

impl std::str::FromStr for EventId {
    type Err = std::num::ParseIntError;

    /// Parses the 16-digit hex form [`std::fmt::Display`] writes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str_radix(s.trim(), 16).map(EventId)
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

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

    #[test]
    fn test_event_id_is_stable_for_identical_content() {
        let origin = Origin::from_hostname("test-server");
        let original_time = Timestamp::from_secs(1_700_000_000);

        let event_a = Event::new(
            Timestamp::now(), // arrival time differs...
            original_time,
            origin.clone(),
            RawData::from_text("same log line"),
        );
        let event_b = Event::new(
            Timestamp::now().add_secs(60), // ...as would happen on redelivery
            original_time,
            origin,
            RawData::from_text("same log line"),
        );

        assert_eq!(event_a.id(), event_b.id());
    }

    /// Pins the exact id for fixed inputs. Ids are stored with events, so
    /// if this test fails the change breaks every stored link: don't update
    /// the constants, revert the hashing change.
    #[test]
    fn test_event_id_golden_values() {
        let text = Event::new(
            Timestamp::from_secs(0),
            Timestamp::from_secs(1_700_000_000),
            Origin::from_hostname("host-a"),
            RawData::from_text("sshd[1]: Accepted password for alice"),
        );
        let json = Event::new(
            Timestamp::from_secs(0),
            Timestamp::from_secs(1_700_000_000),
            Origin::from_ip(Ip::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            RawData::from_json(JsonValue::object(vec![("k", JsonValue::string("v"))])),
        );
        assert_eq!(text.id().to_string(), "d91e831c0863f0f6");
        assert_eq!(json.id().to_string(), "9a1811c1ce8e9b55");
    }

    #[test]
    fn test_stored_id_wins_over_computed() {
        let mut event = Event::new(
            Timestamp::from_secs(0),
            Timestamp::from_secs(1),
            Origin::from_hostname("h"),
            RawData::from_text("x"),
        );
        assert_eq!(event.recorded_id(), None);
        assert_eq!(event.stored_or_computed_id(), event.id());
        event.add_field(
            fields::EVENT_ID.to_string(),
            FieldValue::str("00000000000000ff"),
        );
        assert_eq!(event.recorded_id(), Some(EventId::from_u64(0xff)));
        assert_eq!(event.stored_or_computed_id(), EventId::from_u64(0xff));
    }

    #[test]
    fn test_event_id_differs_for_different_content() {
        let origin = Origin::from_hostname("test-server");
        let original_time = Timestamp::from_secs(1_700_000_000);

        let event_a = Event::new(
            original_time,
            original_time,
            origin.clone(),
            RawData::from_text("log line one"),
        );
        let event_b = Event::new(
            original_time,
            original_time,
            origin,
            RawData::from_text("log line two"),
        );

        assert_ne!(event_a.id(), event_b.id());
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
        let serde_value = serde_json::json!({
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
        let back_to_serde = serde_json::Value::from(our_value);

        // Should be equal
        assert_eq!(serde_value, back_to_serde);
    }

    #[cfg(all(feature = "serde", feature = "json"))]
    #[test]
    fn test_full_event_serde_json_roundtrip() {
        use std::net::Ipv4Addr;

        // A RawData::Json event, round-tripped as a whole Event (not just its
        // Origin/RawData pieces — see event::field::serde_impl for the
        // FieldValue/Timestamp impls and core_serde for Event's own impl).
        let serde_data = serde_json::json!({
            "event_type": "authentication",
            "user": {"id": 123, "name": "admin"},
            "success": true
        });

        let origin = Origin::from_ip(Ip::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let raw_data = RawData::from_json(JsonValue::from(serde_data));
        let mut event = Event::new(Timestamp::now(), Timestamp::now(), origin, raw_data);
        event.add_field("severity".to_string(), FieldValue::Int(9));

        let event_roundtrip: Event =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();

        assert_eq!(event, event_roundtrip);
    }
}
