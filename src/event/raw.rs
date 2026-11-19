use crate::event::field::{FieldValue, Text, Timestamp};
use crate::event::origin::Origin;
use std::collections::HashMap;
use std::fmt;

/// The raw event structure for parser input/output
/// Contains minimal data needed for parsing, optimized for zero-copy operations
#[derive(Debug, Clone)]
pub struct RawEvent {
    /// Original log text that was parsed to create this event
    pub log_text: String,

    /// The source/origin of this event
    pub source: Origin,

    /// Extracted fields (populated during first parsing: Syslog...)
    pub fields: HashMap<Text, FieldValue>,

    /// Timestamp when event arrived
    pub timestamp: Timestamp,
    /// When the event was originally created (from the source system)
    pub original_time: Timestamp,
}

impl RawEvent {
    /// Create a new raw event
    pub fn new(log_text: String, timestamp: Timestamp, source: Origin) -> Self {
        Self {
            log_text,
            source,
            fields: HashMap::new(),
            timestamp,
            original_time: timestamp,
        }
    }

    /// Create a RawEvent from log text and source for parser input
    pub fn from_log(log_text: &str, source: &str) -> Self {
        let timestamp = Timestamp::now();
        Self {
            log_text: log_text.to_string(),
            source: Origin::from_source_string(source),
            fields: HashMap::new(),
            timestamp,
            original_time: timestamp,
        }
    }

    /// Convert this RawEvent into a structured Event
    pub fn into_event(self) -> crate::event::core::Event {
        use crate::event::core::{Event, RawData};

        // Origin is already properly typed
        let origin = self.source;

        // Create Event with proper structure
        let mut event = Event::new(
            self.timestamp,     // arrival_time
            self.original_time, // original_time
            origin,
            RawData::Text(self.log_text),
        );
        // Same map type on both sides: moved, not rebuilt.
        event.fields = self.fields;
        event
    }

    /// Insert a field value
    pub fn insert_field<K, V>(&mut self, key: K, value: V)
    where
        K: Into<Text>,
        V: Into<FieldValue>,
    {
        self.fields.insert(key.into(), value.into());
    }

    /// Get a field value by key
    pub fn get_field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.get(key)
    }

    /// Get a nested field using dot notation
    pub fn get_nested_field<'a>(&'a self, path: &'a str) -> Option<&'a FieldValue> {
        if let Some(field_name) = path.split('.').next() {
            if let Some(field) = self.fields.get(field_name) {
                if path.contains('.') {
                    let remaining_path = &path[field_name.len() + 1..];
                    field.get_nested_field(remaining_path)
                } else {
                    Some(field)
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Create nested object structure
    pub fn insert_nested_field<V>(&mut self, path: &str, value: V)
    where
        V: Into<FieldValue>,
    {
        // Use find to avoid collecting the entire split iterator
        if let Some(dot_pos) = path.find('.') {
            let first_part = &path[..dot_pos];
            let remaining_part = &path[dot_pos + 1..];

            // Build the nested structure using optimized method
            self.insert_nested_field_optimized(first_part, remaining_part, value.into());
        } else {
            // No dots, just insert directly
            self.fields.insert(Text::from(path), value.into());
        }
    }

    fn insert_nested_field_optimized(
        &mut self,
        first_part: &str,
        remaining_path: &str,
        value: FieldValue,
    ) {
        let key = Text::from(first_part);

        // Check if we have more nesting by looking for dots in remaining path
        if !remaining_path.contains('.') {
            // This is the final level - create intermediate object and insert
            let entry = self
                .fields
                .entry(key)
                .or_insert_with(|| FieldValue::Object(HashMap::new()));

            match entry {
                FieldValue::Object(map) => {
                    map.insert(Text::from(remaining_path), value);
                }
                _ => {
                    // Replace with object and insert
                    let mut new_map = HashMap::new();
                    new_map.insert(Text::from(remaining_path), value);
                    *entry = FieldValue::Object(new_map);
                }
            }
        } else {
            // More nesting needed - recurse
            let entry = self
                .fields
                .entry(key)
                .or_insert_with(|| FieldValue::Object(HashMap::new()));

            match entry {
                FieldValue::Object(map) => {
                    // Create a temporary RawEvent to handle the nested insertion
                    let mut temp_event = RawEvent {
                        log_text: String::new(),
                        fields: std::mem::take(map),
                        timestamp: self.timestamp,
                        original_time: self.timestamp,
                        source: Origin::Hostname(String::new()),
                    };
                    temp_event.insert_nested_field(remaining_path, value);
                    *map = temp_event.fields;
                }
                _ => {
                    // Replace with object and continue
                    *entry = FieldValue::Object(HashMap::new());
                    if let FieldValue::Object(map) = entry {
                        let mut temp_event = RawEvent {
                            log_text: String::new(),
                            fields: std::mem::take(map),
                            timestamp: self.timestamp,
                            original_time: self.timestamp,
                            source: Origin::Hostname(String::new()),
                        };
                        temp_event.insert_nested_field(remaining_path, value);
                        *map = temp_event.fields;
                    }
                }
            }
        }
    }

    /// Get all field names (including nested ones with dot notation)
    pub fn get_all_field_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        self.collect_field_names("", &self.fields, &mut names);
        names
    }

    fn collect_field_names(
        &self,
        prefix: &str,
        fields: &HashMap<Text, FieldValue>,
        names: &mut Vec<String>,
    ) {
        for (key, value) in fields {
            let full_key = if prefix.is_empty() {
                key.to_string()
            } else {
                format!("{}.{}", prefix, key)
            };

            names.push(full_key.clone());

            if let FieldValue::Object(nested_fields) = value {
                self.collect_field_names(&full_key, nested_fields, names);
            }
        }
    }
}

impl fmt::Display for RawEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RawEvent {{ timestamp: {}, source: {}, fields: {} }}",
            self.timestamp,
            self.source,
            self.fields.len()
        )
    }
}
