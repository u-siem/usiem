use std::borrow::Cow;
use std::collections::HashMap;

use super::field_value::FieldValue;
use super::ip::Ip;
use super::text::Text;
use super::time::Timestamp;

// Ergonomic From implementations for common types
impl From<&'static str> for FieldValue {
    fn from(s: &'static str) -> Self {
        FieldValue::Str(Cow::Borrowed(s))
    }
}

impl From<String> for FieldValue {
    fn from(s: String) -> Self {
        FieldValue::Str(Cow::Owned(s))
    }
}

impl From<i64> for FieldValue {
    fn from(value: i64) -> Self {
        FieldValue::Int(value)
    }
}

impl From<u64> for FieldValue {
    fn from(value: u64) -> Self {
        FieldValue::Uint(value)
    }
}

impl From<i32> for FieldValue {
    fn from(value: i32) -> Self {
        FieldValue::Int(value as i64)
    }
}

impl From<u32> for FieldValue {
    fn from(value: u32) -> Self {
        FieldValue::Uint(value as u64)
    }
}

impl From<f64> for FieldValue {
    fn from(value: f64) -> Self {
        FieldValue::Float(value)
    }
}

impl From<f32> for FieldValue {
    fn from(value: f32) -> Self {
        FieldValue::Float(value as f64)
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        FieldValue::Bool(value)
    }
}

impl From<Vec<u8>> for FieldValue {
    fn from(value: Vec<u8>) -> Self {
        FieldValue::Bytes(value)
    }
}

impl From<Timestamp> for FieldValue {
    fn from(value: Timestamp) -> Self {
        FieldValue::Time(value)
    }
}

impl From<Ip> for FieldValue {
    fn from(value: Ip) -> Self {
        FieldValue::Ip(value)
    }
}

impl From<HashMap<Text, FieldValue>> for FieldValue {
    fn from(value: HashMap<Text, FieldValue>) -> Self {
        FieldValue::Object(value)
    }
}

impl From<Vec<FieldValue>> for FieldValue {
    fn from(value: Vec<FieldValue>) -> Self {
        FieldValue::Array(value)
    }
}
