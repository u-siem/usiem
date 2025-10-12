use std::collections::HashMap;
use std::fmt;

/// A simple JSON-like value representation for structured event data
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// JSON null value
    Null,
    /// JSON boolean value
    Bool(bool),
    /// JSON number value (stored as f64 for simplicity)
    Number(f64),
    /// JSON string value
    String(String),
    /// JSON array value
    Array(Vec<JsonValue>),
    /// JSON object value
    Object(HashMap<String, JsonValue>),
}

impl JsonValue {
    /// Create a new null value
    pub fn null() -> Self {
        JsonValue::Null
    }

    /// Create a new boolean value
    pub fn bool(value: bool) -> Self {
        JsonValue::Bool(value)
    }

    /// Create a new number value from any numeric type
    pub fn number<T: Into<f64>>(value: T) -> Self {
        JsonValue::Number(value.into())
    }

    /// Create a new string value
    pub fn string<S: Into<String>>(value: S) -> Self {
        JsonValue::String(value.into())
    }

    /// Create a new array value
    pub fn array<I: IntoIterator<Item = JsonValue>>(items: I) -> Self {
        JsonValue::Array(items.into_iter().collect())
    }

    /// Create a new object value
    pub fn object<I, K, V>(items: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<JsonValue>,
    {
        JsonValue::Object(
            items
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }

    /// Check if the value is null
    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    /// Check if the value is a boolean
    pub fn is_bool(&self) -> bool {
        matches!(self, JsonValue::Bool(_))
    }

    /// Check if the value is a number
    pub fn is_number(&self) -> bool {
        matches!(self, JsonValue::Number(_))
    }

    /// Check if the value is a string
    pub fn is_string(&self) -> bool {
        matches!(self, JsonValue::String(_))
    }

    /// Check if the value is an array
    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    /// Check if the value is an object
    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }

    /// Get the value as a boolean, if it is one
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get the value as a number, if it is one
    pub fn as_number(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Get the value as a string reference, if it is one
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the value as an array reference, if it is one
    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Get the value as an object reference, if it is one
    pub fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
        match self {
            JsonValue::Object(obj) => Some(obj),
            _ => None,
        }
    }

    /// Get a value from an object by key
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(obj) => obj.get(key),
            _ => None,
        }
    }

    /// Get a value from an array by index
    pub fn get_index(&self, index: usize) -> Option<&JsonValue> {
        match self {
            JsonValue::Array(arr) => arr.get(index),
            _ => None,
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonValue::Null => write!(f, "null"),
            JsonValue::Bool(b) => write!(f, "{}", b),
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && n.is_finite() {
                    write!(f, "{:.0}", n)
                } else {
                    write!(f, "{}", n)
                }
            }
            JsonValue::String(s) => write!(f, "\"{}\"", escape_json_string(s)),
            JsonValue::Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
            JsonValue::Object(obj) => {
                write!(f, "{{")?;
                for (i, (key, value)) in obj.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "\"{}\":{}", escape_json_string(key), value)?;
                }
                write!(f, "}}")
            }
        }
    }
}

/// Simple JSON string escaping (basic implementation)
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// Conversion traits for ergonomic API
impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        JsonValue::Bool(value)
    }
}

impl From<i32> for JsonValue {
    fn from(value: i32) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<f32> for JsonValue {
    fn from(value: f32) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<f64> for JsonValue {
    fn from(value: f64) -> Self {
        JsonValue::Number(value)
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        JsonValue::String(value)
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        JsonValue::String(value.to_string())
    }
}

impl<T: Into<JsonValue>> From<Vec<T>> for JsonValue {
    fn from(value: Vec<T>) -> Self {
        JsonValue::Array(value.into_iter().map(|item| item.into()).collect())
    }
}

impl<K: Into<String>, V: Into<JsonValue>> From<HashMap<K, V>> for JsonValue {
    fn from(value: HashMap<K, V>) -> Self {
        JsonValue::Object(
            value
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_value_creation() {
        let null_val = JsonValue::null();
        let bool_val = JsonValue::bool(true);
        let num_val = JsonValue::number(42.5);
        let str_val = JsonValue::string("hello");
        let arr_val = JsonValue::array(vec![JsonValue::number(1), JsonValue::number(2)]);

        assert!(null_val.is_null());
        assert!(bool_val.is_bool());
        assert!(num_val.is_number());
        assert!(str_val.is_string());
        assert!(arr_val.is_array());
    }

    #[test]
    fn test_json_value_accessors() {
        let bool_val = JsonValue::bool(true);
        let num_val = JsonValue::number(42.0);
        let str_val = JsonValue::string("test");

        assert_eq!(bool_val.as_bool(), Some(true));
        assert_eq!(num_val.as_number(), Some(42.0));
        assert_eq!(str_val.as_str(), Some("test"));
    }

    #[test]
    fn test_json_object_access() {
        let mut obj = HashMap::new();
        obj.insert("key1".to_string(), JsonValue::string("value1"));
        obj.insert("key2".to_string(), JsonValue::number(123));

        let json_obj = JsonValue::Object(obj);

        assert_eq!(json_obj.get("key1"), Some(&JsonValue::string("value1")));
        assert_eq!(json_obj.get("key2"), Some(&JsonValue::number(123)));
        assert_eq!(json_obj.get("nonexistent"), None);
    }

    #[test]
    fn test_json_array_access() {
        let arr = JsonValue::array(vec![
            JsonValue::string("first"),
            JsonValue::number(42),
            JsonValue::bool(true),
        ]);

        assert_eq!(arr.get_index(0), Some(&JsonValue::string("first")));
        assert_eq!(arr.get_index(1), Some(&JsonValue::number(42)));
        assert_eq!(arr.get_index(2), Some(&JsonValue::bool(true)));
        assert_eq!(arr.get_index(3), None);
    }

    #[test]
    fn test_json_display() {
        let obj = JsonValue::object(vec![
            ("name", JsonValue::string("test")),
            ("count", JsonValue::number(42)),
            ("active", JsonValue::bool(true)),
        ]);

        let display_str = obj.to_string();
        assert!(display_str.contains("\"name\":\"test\""));
        assert!(display_str.contains("\"count\":42"));
        assert!(display_str.contains("\"active\":true"));
    }

    #[test]
    fn test_conversion_traits() {
        let from_bool: JsonValue = true.into();
        let from_int: JsonValue = 42i32.into();
        let from_str: JsonValue = "hello".into();
        let from_vec: JsonValue = vec![1i32, 2i32, 3i32].into();

        assert!(from_bool.is_bool());
        assert!(from_int.is_number());
        assert!(from_str.is_string());
        assert!(from_vec.is_array());
    }
}
