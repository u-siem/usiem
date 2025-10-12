use super::{FieldValue, Ip, Text, Timestamp};
use std::collections::HashMap;

/// Fluent object builder for ergonomic FieldValue::Object creation
/// Automatically converts values to FieldValue without requiring .into()
#[derive(Debug, Clone)]
pub struct ObjectBuilder {
    fields: HashMap<Text, FieldValue>,
}

impl ObjectBuilder {
    /// Create a new empty object builder
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Insert a field with automatic conversion to FieldValue
    /// Supports dot notation for nested objects (e.g., "process.name" -> { "process": { "name": value } })
    pub fn field<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<Text>,
        V: Into<FieldValue>,
    {
        self.insert(key, value.into());
        self
    }

    /// Insert a field with mutable reference (for chaining)
    /// Supports dot notation for nested objects (e.g., "process.name" -> { "process": { "name": value } })
    pub fn with<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: Into<Text>,
        V: Into<FieldValue>,
    {
        self.insert(key, value.into());
        self
    }

    /// Insert a string field (optimized for static strings)
    /// Supports dot notation for nested objects
    pub fn str<K>(mut self, key: K, value: &'static str) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::str(value));
        self
    }

    /// Insert an owned string field
    /// Supports dot notation for nested objects
    pub fn string<K>(mut self, key: K, value: String) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::string(value));
        self
    }

    /// Insert an integer field
    /// Supports dot notation for nested objects
    pub fn int<K>(mut self, key: K, value: i64) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::int(value));
        self
    }

    /// Insert an unsigned integer field
    /// Supports dot notation for nested objects
    pub fn uint<K>(mut self, key: K, value: u64) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::uint(value));
        self
    }

    /// Insert a float field
    /// Supports dot notation for nested objects
    pub fn float<K>(mut self, key: K, value: f64) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::float(value));
        self
    }

    /// Insert a boolean field
    /// Supports dot notation for nested objects
    pub fn bool<K>(mut self, key: K, value: bool) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::bool(value));
        self
    }

    /// Insert a timestamp field
    /// Supports dot notation for nested objects
    pub fn time<K>(mut self, key: K, value: Timestamp) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::Time(value));
        self
    }

    /// Insert an IP address field
    /// Supports dot notation for nested objects
    pub fn ip<K>(mut self, key: K, value: Ip) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::Ip(value));
        self
    }

    /// Insert a bytes field
    /// Supports dot notation for nested objects
    pub fn bytes<K>(mut self, key: K, value: Vec<u8>) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::Bytes(value));
        self
    }

    /// Insert a nested object field
    /// Supports dot notation for nested objects
    pub fn object<K>(mut self, key: K, value: ObjectBuilder) -> Self
    where
        K: Into<Text>,
    {
        self.insert(key, FieldValue::Object(value.fields));
        self
    }

    /// Insert an array field
    /// Supports dot notation for nested objects
    pub fn array<K, I, V>(mut self, key: K, values: I) -> Self
    where
        K: Into<Text>,
        I: IntoIterator<Item = V>,
        V: Into<FieldValue>,
    {
        let array: Vec<FieldValue> = values.into_iter().map(|v| v.into()).collect();
        self.insert(key, FieldValue::Array(array));
        self
    }

    /// Insert multiple fields from an iterator
    /// Supports dot notation for nested objects
    pub fn fields<I, K, V>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<Text>,
        V: Into<FieldValue>,
    {
        for (key, value) in iter {
            self.insert(key, value.into());
        }
        self
    }

    /// Set the timestamp to now
    pub fn now(self) -> Self {
        self.time("timestamp", Timestamp::now())
    }

    /// Set a custom timestamp
    pub fn timestamp<K>(self, key: K, timestamp: Timestamp) -> Self
    where
        K: Into<Text>,
    {
        self.time(key, timestamp)
    }

    /// Insert method that handles both regular and nested fields
    /// Automatically detects dot notation and creates nested objects as needed
    pub fn insert<K>(&mut self, key: K, value: FieldValue)
    where
        K: Into<Text>,
    {
        let key_text = key.into();
        let key_str = key_text.as_ref();

        if key_str.contains('.') {
            self.insert_nested(&key_text, value);
        } else {
            self.fields.insert(key_text, value);
        }
    }

    /// Helper method to insert nested fields using dot notation
    fn insert_nested(&mut self, key: &Text, value: FieldValue) {
        let key_str = key.as_ref();

        // Find the first dot position to split efficiently without collecting
        if let Some(dot_pos) = key_str.find('.') {
            let first_part = &key_str[..dot_pos];
            let remaining_part = &key_str[dot_pos + 1..];

            let first_key = first_part.to_owned().into();

            // Get or create the nested object
            let nested_obj = self
                .fields
                .entry(first_key)
                .or_insert_with(|| FieldValue::Object(HashMap::new()));

            // Ensure it's an object
            if !matches!(nested_obj, FieldValue::Object(_)) {
                *nested_obj = FieldValue::Object(HashMap::new());
            }

            // If remaining part has no dots, this is the final level
            if !remaining_part.contains('.') {
                if let FieldValue::Object(map) = nested_obj {
                    map.insert(remaining_part.to_owned().into(), value);
                }
            } else {
                // More nesting needed, recurse
                if let FieldValue::Object(map) = nested_obj {
                    let remaining_key: Text = remaining_part.to_owned().into();
                    let mut nested_builder = ObjectBuilder {
                        fields: std::mem::take(map),
                    };
                    nested_builder.insert_nested(&remaining_key, value);
                    *map = nested_builder.fields;
                }
            }
        } else {
            // No dots, just insert normally
            self.fields.insert(key.clone(), value);
        }
    }

    /// Build into a FieldValue::Object
    pub fn build(self) -> FieldValue {
        FieldValue::Object(self.fields)
    }

    /// Build into the raw HashMap
    pub fn into_map(self) -> HashMap<Text, FieldValue> {
        self.fields
    }

    /// Get the current number of fields
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Get a reference to a field if it exists
    /// Supports dot notation for nested field access (e.g., "process.name", "network.source.ip")
    pub fn get<K>(&self, key: K) -> Option<&FieldValue>
    where
        K: Into<Text>,
    {
        let key_text = key.into();
        let key_str = key_text.as_ref();

        if key_str.contains('.') {
            // Use nested field access by implementing it directly
            self.get_nested_field(key_str)
        } else {
            // Regular field access
            self.fields.get(&key_text)
        }
    }

    /// Get nested field by dot-separated path directly from the builder's fields
    fn get_nested_field(&self, path: &str) -> Option<&FieldValue> {
        let mut parts = path.split('.');

        // Get the first part
        let first_part = parts.next()?;

        // Start with the first part from root fields
        let mut current = self.fields.get(first_part as &str)?;

        // Traverse the rest of the path using the iterator directly
        for part in parts {
            match current {
                FieldValue::Object(map) => {
                    current = map.get(part as &str)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }

    /// Check if a field exists
    /// Supports dot notation for nested field checking (e.g., "process.name", "network.source.ip")
    pub fn contains_key<K>(&self, key: K) -> bool
    where
        K: Into<Text>,
    {
        let key_text = key.into();
        let key_str = key_text.as_ref();

        if key_str.contains('.') {
            // Check nested field exists
            self.get_nested_field(key_str).is_some()
        } else {
            // Regular field check
            self.fields.contains_key(&key_text)
        }
    }

    /// Get a fluent field getter for chaining operations
    /// Supports dot notation for nested field access (e.g., "process.name", "network.source.ip")
    /// Returns a FieldGetter that provides convenient type conversion and operations
    pub fn getter<K>(&self, key: K) -> super::getter::FieldGetter<'_>
    where
        K: Into<Text>,
    {
        let key_text = key.into();
        let key_str = key_text.as_ref();

        super::getter::FieldGetter {
            field: if key_str.contains('.') {
                self.get_nested_field(key_str)
            } else {
                self.fields.get(&key_text)
            },
            path: std::borrow::Cow::Owned(key_str.to_owned()),
        }
    }
}

impl Default for ObjectBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ObjectBuilder> for FieldValue {
    fn from(builder: ObjectBuilder) -> Self {
        builder.build()
    }
}

impl From<ObjectBuilder> for HashMap<Text, FieldValue> {
    fn from(builder: ObjectBuilder) -> Self {
        builder.into_map()
    }
}

// Convenient type alias for creating events/objects
pub type Event = ObjectBuilder;
// Legacy alias for backward compatibility
pub type EventBuilder = ObjectBuilder;

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_object_builder_basic() {
        let event = ObjectBuilder::new()
            .str("event_type", "authentication")
            .int("severity", 3)
            .bool("success", true)
            .float("response_time", 125.5)
            .uint("user_id", 12345)
            .build();

        if let FieldValue::Object(map) = event {
            assert_eq!(
                map.get(&Cow::Borrowed("event_type")).unwrap().as_str(),
                Some("authentication")
            );
            assert_eq!(
                map.get(&Cow::Borrowed("severity")).unwrap().as_i64(),
                Some(3)
            );
            assert_eq!(
                map.get(&Cow::Borrowed("success")).unwrap().as_bool(),
                Some(true)
            );
            assert_eq!(
                map.get(&Cow::Borrowed("response_time")).unwrap().as_f64(),
                Some(125.5)
            );
            assert_eq!(
                map.get(&Cow::Borrowed("user_id")).unwrap().as_u64(),
                Some(12345)
            );
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn test_object_builder_field_method() {
        let event = ObjectBuilder::new()
            .field("name", "test")
            .field("count", 42)
            .field("active", true)
            .build();

        if let FieldValue::Object(map) = event {
            assert_eq!(map.len(), 3);
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn test_object_builder_nested() {
        let source_info = ObjectBuilder::new()
            .str("ip", "192.168.1.100")
            .uint("port", 443)
            .str("country", "US");

        let event = ObjectBuilder::new()
            .str("event_type", "authentication")
            .object("source", source_info)
            .build();

        if let FieldValue::Object(map) = event {
            if let Some(FieldValue::Object(source_map)) = map.get(&Cow::Borrowed("source")) {
                assert_eq!(
                    source_map.get(&Cow::Borrowed("ip")).unwrap().as_str(),
                    Some("192.168.1.100")
                );
                assert_eq!(
                    source_map.get(&Cow::Borrowed("port")).unwrap().as_u64(),
                    Some(443)
                );
            } else {
                panic!("Expected nested object");
            }
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn test_object_builder_array() {
        let event = ObjectBuilder::new()
            .str("event_type", "multi_event")
            .array("tags", vec!["security", "authentication", "login"])
            .array("codes", vec![200, 404, 500])
            .build();

        if let FieldValue::Object(map) = event {
            if let Some(FieldValue::Array(tags)) = map.get(&Cow::Borrowed("tags")) {
                assert_eq!(tags.len(), 3);
                assert_eq!(tags[0].as_str(), Some("security"));
            } else {
                panic!("Expected array");
            }

            if let Some(FieldValue::Array(codes)) = map.get(&Cow::Borrowed("codes")) {
                assert_eq!(codes.len(), 3);
                assert_eq!(codes[0].as_i64(), Some(200));
            } else {
                panic!("Expected array");
            }
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn test_object_builder_mutable() {
        let mut builder = ObjectBuilder::new();
        builder.with("name", "test").with("count", 42);

        let event = builder.build();

        if let FieldValue::Object(map) = event {
            assert_eq!(map.len(), 2);
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn test_object_builder_now() {
        let event = ObjectBuilder::new().str("event_type", "test").now().build();

        if let FieldValue::Object(map) = event {
            assert!(map.contains_key(&Cow::Borrowed("timestamp")));
            if let Some(FieldValue::Time(_)) = map.get(&Cow::Borrowed("timestamp")) {
                // Timestamp exists and is correct type
            } else {
                panic!("Expected timestamp field");
            }
        } else {
            panic!("Expected Object variant");
        }
    }
}
