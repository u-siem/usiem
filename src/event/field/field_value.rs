use std::borrow::Cow;
use std::cmp::PartialEq;
use std::collections::HashMap;

use super::error::FieldConversionError;
use super::getter::FieldGetter;
use super::ip::Ip;
use super::specialized::{Domain, Email, ParseError, Url};
use super::text::Text;
use super::time::Timestamp;

/// Field value that can hold different types with Cow strings for performance
/// and specialized types for time and IP addresses
#[derive(Debug, Clone)]
pub enum FieldValue {
    Str(Text),
    Int(i64),
    Uint(u64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    Time(Timestamp),
    Ip(Ip),
    Object(HashMap<Text, FieldValue>),
    Array(Vec<FieldValue>),
}

impl PartialEq for FieldValue {
    fn eq(&self, other: &Self) -> bool {
        use FieldValue::*;
        match (self, other) {
            // Exact type matches
            (Str(a), Str(b)) => a == b,
            (Bool(a), Bool(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Time(a), Time(b)) => a == b,
            (Ip(a), Ip(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Object(a), Object(b)) => a == b,

            // Numeric cross-type comparisons
            (Int(a), Int(b)) => a == b,
            (Uint(a), Uint(b)) => a == b,
            (Float(a), Float(b)) => a == b,

            // Int with Uint: check if non-negative int equals uint
            (Int(a), Uint(b)) => *a >= 0 && (*a as u64) == *b,
            (Uint(a), Int(b)) => *b >= 0 && *a == (*b as u64),

            // Int with Float: convert int to float for comparison
            (Int(a), Float(b)) => (*a as f64) == *b,
            (Float(a), Int(b)) => *a == (*b as f64),

            // Uint with Float: convert uint to float for comparison
            (Uint(a), Float(b)) => (*a as f64) == *b,
            (Float(a), Uint(b)) => *a == (*b as f64),

            // All other combinations are not equal
            _ => false,
        }
    }
}

impl FieldValue {
    /// Create a FieldValue::Str from a static string (ergonomic constructor)
    pub fn str(s: &'static str) -> Self {
        FieldValue::Str(Cow::Borrowed(s))
    }

    /// Create a FieldValue::Str from an owned string (ergonomic constructor)
    pub fn string(s: String) -> Self {
        FieldValue::Str(Cow::Owned(s))
    }

    /// Create a FieldValue::Int (ergonomic constructor)
    pub fn int(value: i64) -> Self {
        FieldValue::Int(value)
    }

    /// Create a FieldValue::Uint (ergonomic constructor)
    pub fn uint(value: u64) -> Self {
        FieldValue::Uint(value)
    }

    /// Create a FieldValue::Float (ergonomic constructor)
    pub fn float(value: f64) -> Self {
        FieldValue::Float(value)
    }

    /// Create a FieldValue::Bool (ergonomic constructor)
    pub fn bool(value: bool) -> Self {
        FieldValue::Bool(value)
    }

    /// Cast to string without allocation if already a string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(s) => Some(s.as_ref()),
            _ => None,
        }
    }

    /// Cast to i64 with parsing if needed
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Int(i) => Some(*i),
            FieldValue::Uint(u) => {
                if *u <= i64::MAX as u64 {
                    Some(*u as i64)
                } else {
                    None
                }
            }
            FieldValue::Float(f) => {
                if f.fract() == 0.0 && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 {
                    Some(*f as i64)
                } else {
                    None
                }
            }
            FieldValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Cast to u64 with parsing if needed
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            FieldValue::Uint(u) => Some(*u),
            FieldValue::Int(i) => {
                if *i >= 0 {
                    Some(*i as u64)
                } else {
                    None
                }
            }
            FieldValue::Float(f) => {
                if f.fract() == 0.0 && *f >= 0.0 && *f <= u64::MAX as f64 {
                    Some(*f as u64)
                } else {
                    None
                }
            }
            FieldValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Cast to u32 with parsing if needed
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            FieldValue::Uint(u) => {
                if *u <= u32::MAX as u64 {
                    Some(*u as u32)
                } else {
                    None
                }
            }
            FieldValue::Int(i) => {
                if *i >= 0 && *i <= u32::MAX as i64 {
                    Some(*i as u32)
                } else {
                    None
                }
            }
            FieldValue::Float(f) => {
                if f.fract() == 0.0 && *f >= 0.0 && *f <= u32::MAX as f64 {
                    Some(*f as u32)
                } else {
                    None
                }
            }
            FieldValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Cast to f64 with parsing if needed
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            FieldValue::Float(f) => Some(*f),
            FieldValue::Int(i) => Some(*i as f64),
            FieldValue::Uint(u) => Some(*u as f64),
            FieldValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Cast to bool with parsing if needed
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            FieldValue::Bool(b) => Some(*b),
            FieldValue::Int(i) => Some(*i != 0),
            FieldValue::Uint(u) => Some(*u != 0),
            FieldValue::Str(s) => match s.to_lowercase().as_str() {
                "true" | "yes" | "1" | "on" => Some(true),
                "false" | "no" | "0" | "off" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// Cast to Timestamp if applicable
    pub fn as_time(&self) -> Option<Timestamp> {
        match self {
            FieldValue::Time(t) => Some(*t),
            FieldValue::Int(i) => Some(Timestamp::from_nanos(*i)),
            FieldValue::Uint(i) => Some(Timestamp::from_nanos(*i as _)),
            FieldValue::Str(s) => Timestamp::from_rfc3339(s).ok(),
            _ => None,
        }
    }

    /// Cast to Ip if applicable
    pub fn as_ip(&self) -> Option<Ip> {
        match self {
            FieldValue::Ip(ip) => Some(*ip),
            FieldValue::Str(s) => s.parse::<std::net::IpAddr>().ok().map(Ip::from),
            _ => None,
        }
    }

    /// Get the type name as a static string
    pub fn type_name(&self) -> &'static str {
        match self {
            FieldValue::Str(_) => "Str",
            FieldValue::Int(_) => "Int",
            FieldValue::Uint(_) => "Uint",
            FieldValue::Float(_) => "Float",
            FieldValue::Bool(_) => "Bool",
            FieldValue::Bytes(_) => "Bytes",
            FieldValue::Time(_) => "Time",
            FieldValue::Ip(_) => "Ip",
            FieldValue::Object(_) => "Object",
            FieldValue::Array(_) => "Array",
        }
    }

    /// Check if the value can be copied (for performance optimization)
    pub fn is_copyable(&self) -> bool {
        !matches!(
            self,
            FieldValue::Str(_)
                | FieldValue::Bytes(_)
                | FieldValue::Object(_)
                | FieldValue::Array(_)
        )
    }

    /// Copy the value if it's copyable, otherwise return None
    pub fn copy_if_copyable(&self) -> Option<FieldValue> {
        match self {
            FieldValue::Int(i) => Some(FieldValue::Int(*i)),
            FieldValue::Uint(u) => Some(FieldValue::Uint(*u)),
            FieldValue::Float(f) => Some(FieldValue::Float(*f)),
            FieldValue::Bool(b) => Some(FieldValue::Bool(*b)),
            FieldValue::Time(t) => Some(FieldValue::Time(*t)),
            FieldValue::Ip(ip) => Some(FieldValue::Ip(*ip)),
            _ => None,
        }
    }

    /// Get nested field by dot-separated path  
    pub fn get_nested_field<'a>(&'a self, path: &'a str) -> Option<&'a FieldValue> {
        let mut current = self;

        // Use iterator directly to avoid allocation
        for part in path.split('.') {
            match current {
                FieldValue::Object(map) => {
                    current = map.get(&Cow::Borrowed(part))?;
                }
                _ => return None,
            }
        }
        Some(current)
    }

    /// Fluent field getter - returns a FieldGetter for chaining
    pub fn get<'a>(&'a self, path: &'a str) -> FieldGetter<'a> {
        FieldGetter {
            field: if path.contains('.') {
                self.get_nested_field(path)
            } else {
                match self {
                    FieldValue::Object(map) => map.get(&Cow::Borrowed(path)),
                    _ => None,
                }
            },
            path: Cow::Borrowed(path),
        }
    }

    /// Enhanced fluent access methods for ergonomics
    pub fn as_i64_or(&self, default: i64) -> i64 {
        self.as_i64().unwrap_or(default)
    }

    /// Enhanced fluent access methods for ergonomics
    pub fn as_u64_or(&self, default: u64) -> u64 {
        self.as_u64().unwrap_or(default)
    }

    /// Enhanced fluent access methods for ergonomics
    pub fn as_f64_or(&self, default: f64) -> f64 {
        self.as_f64().unwrap_or(default)
    }

    /// Enhanced fluent access methods for ergonomics
    pub fn as_str_or(&self, default: &str) -> String {
        self.as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| default.to_string())
    }

    // ===== String Utility Methods =====

    /// Check if string field contains the given substring (case sensitive)
    pub fn contains(&self, needle: &str) -> bool {
        self.as_str().map_or(false, |s| s.contains(needle))
    }

    /// Check if string field contains the given substring (case insensitive)
    pub fn contains_ignore_case(&self, needle: &str) -> bool {
        self.as_str()
            .map_or(false, |s| s.to_lowercase().contains(&needle.to_lowercase()))
    }

    /// Check if string field starts with the given prefix (case sensitive)
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().map_or(false, |s| s.starts_with(prefix))
    }

    /// Check if string field starts with the given prefix (case insensitive)
    pub fn starts_with_ignore_case(&self, prefix: &str) -> bool {
        self.as_str().map_or(false, |s| {
            s.to_lowercase().starts_with(&prefix.to_lowercase())
        })
    }

    /// Check if string field ends with the given suffix (case sensitive)
    pub fn ends_with(&self, suffix: &str) -> bool {
        self.as_str().map_or(false, |s| s.ends_with(suffix))
    }

    /// Check if string field ends with the given suffix (case insensitive)
    pub fn ends_with_ignore_case(&self, suffix: &str) -> bool {
        self.as_str().map_or(false, |s| {
            s.to_lowercase().ends_with(&suffix.to_lowercase())
        })
    }

    /// Check if string field equals the given string (case sensitive)
    pub fn equals(&self, other: &str) -> bool {
        self.as_str().map_or(false, |s| s == other)
    }

    /// Check if string field equals the given string (case insensitive)
    pub fn equals_ignore_case(&self, other: &str) -> bool {
        self.as_str()
            .map_or(false, |s| s.to_lowercase() == other.to_lowercase())
    }

    /// Get the length of the string field (returns 0 for non-string fields)
    pub fn len(&self) -> usize {
        self.as_str().map_or(0, |s| s.len())
    }

    /// Check if string field is empty (returns true for non-string fields)
    pub fn is_empty(&self) -> bool {
        self.as_str().map_or(true, |s| s.is_empty())
    }

    /// Convert string field to lowercase (returns empty string for non-string fields)
    pub fn to_lowercase(&self) -> String {
        self.as_str().map_or(String::new(), |s| s.to_lowercase())
    }

    /// Convert string field to uppercase (returns empty string for non-string fields)
    pub fn to_uppercase(&self) -> String {
        self.as_str().map_or(String::new(), |s| s.to_uppercase())
    }

    /// Trim whitespace from string field (returns empty string for non-string fields)
    pub fn trim<'a>(&'a self) -> &'a str {
        self.as_str().map_or("", |s| s.trim())
    }

    /// Split string field by delimiter (returns empty vec for non-string fields)
    pub fn split<'a>(&'a self, delimiter: &str) -> Vec<&'a str> {
        self.as_str()
            .map_or(Vec::new(), |s| s.split(delimiter).collect())
    }

    /// Check if string field matches a regex pattern (returns false for non-string fields)
    /// Note: This is a simple contains check, not a full regex implementation
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        self.contains(pattern)
    }

    // ===== Specialized Type Extraction =====

    /// Try to extract an email address from the string field
    pub fn as_email(&self) -> Result<Email<'_>, ParseError> {
        match self.as_str() {
            Some(s) => Email::try_from_str(s),
            None => Err(ParseError::InvalidFormat("Field is not a string")),
        }
    }

    /// Try to extract a domain from the string field
    pub fn as_domain(&self) -> Result<Domain<'_>, ParseError> {
        match self.as_str() {
            Some(s) => Domain::try_from_str(s),
            None => Err(ParseError::InvalidFormat("Field is not a string")),
        }
    }

    /// Try to extract a URL from the string field
    pub fn as_url(&self) -> Result<Url<'_>, ParseError> {
        match self.as_str() {
            Some(s) => Url::try_from_str(s),
            None => Err(ParseError::InvalidFormat("Field is not a string")),
        }
    }

    /// Enhanced fluent access methods for ergonomics
    pub fn as_bool_or(&self, default: bool) -> bool {
        self.as_bool().unwrap_or(default)
    }

    /// Extract as specific type with error handling
    pub fn extract<T>(&self) -> Result<T, FieldConversionError>
    where
        T: for<'a> TryFrom<&'a FieldValue, Error = FieldConversionError>,
    {
        T::try_from(self)
    }

    /// Extract with default fallback
    pub fn extract_or<T>(&self, default: T) -> T
    where
        T: for<'a> TryFrom<&'a FieldValue, Error = FieldConversionError>,
    {
        self.extract().unwrap_or(default)
    }

    /// Require field extraction or panic
    pub fn require<T>(&self, field_name: &str) -> T
    where
        T: for<'a> TryFrom<&'a FieldValue, Error = FieldConversionError>,
    {
        self.extract()
            .unwrap_or_else(|e| panic!("Required field '{}' extraction failed: {}", field_name, e))
    }

    // === Array Set-like Operations ===

    /// Check if an array contains a specific element (case-sensitive)
    pub fn array_contains(&self, element: &FieldValue) -> bool {
        match self {
            FieldValue::Array(arr) => arr.iter().any(|item| item == element),
            _ => false,
        }
    }

    /// Check if an array contains a specific string element (case-sensitive)
    pub fn array_contains_str(&self, element: &str) -> bool {
        match self {
            FieldValue::Array(arr) => arr.iter().any(|item| match item {
                FieldValue::Str(s) => s == element,
                _ => false,
            }),
            _ => false,
        }
    }

    /// Check if an array contains a specific string element (case-insensitive)
    pub fn array_contains_str_ignore_case(&self, element: &str) -> bool {
        match self {
            FieldValue::Array(arr) => {
                let element_lower = element.to_lowercase();
                arr.iter().any(|item| match item {
                    FieldValue::Str(s) => s.to_lowercase() == element_lower,
                    _ => false,
                })
            }
            _ => false,
        }
    }

    /// Check if an array contains any of the given elements (case-sensitive)
    pub fn array_contains_any_str(&self, elements: &[&str]) -> bool {
        elements
            .iter()
            .any(|element| self.array_contains_str(element))
    }

    /// Check if an array contains any of the given elements (case-insensitive)
    pub fn array_contains_any_str_ignore_case(&self, elements: &[&str]) -> bool {
        elements
            .iter()
            .any(|element| self.array_contains_str_ignore_case(element))
    }

    /// Check if an array contains all of the given elements (case-sensitive)
    pub fn array_contains_all_str(&self, elements: &[&str]) -> bool {
        elements
            .iter()
            .all(|element| self.array_contains_str(element))
    }

    /// Check if an array contains all of the given elements (case-insensitive)
    pub fn array_contains_all_str_ignore_case(&self, elements: &[&str]) -> bool {
        elements
            .iter()
            .all(|element| self.array_contains_str_ignore_case(element))
    }

    /// Get the intersection of array elements with given strings (case-sensitive)
    pub fn array_intersection_str<'a>(&self, elements: &'a [&str]) -> Vec<&'a str> {
        match self {
            FieldValue::Array(arr) => elements
                .iter()
                .filter(|element| {
                    arr.iter().any(|item| {
                        if let FieldValue::Str(s) = item {
                            s.as_ref() == **element
                        } else {
                            false
                        }
                    })
                })
                .copied()
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Get the intersection of array elements with given strings (case-insensitive)
    pub fn array_intersection_str_ignore_case<'a>(&self, elements: &'a [&str]) -> Vec<&'a str> {
        match self {
            FieldValue::Array(arr) => elements
                .iter()
                .filter(|element| {
                    let element_lower = element.to_lowercase();
                    arr.iter().any(|item| {
                        if let FieldValue::Str(s) = item {
                            s.to_lowercase() == element_lower
                        } else {
                            false
                        }
                    })
                })
                .copied()
                .collect(),
            _ => Vec::new(),
        }
    }

    // === CommandLine Parsing ===

    /// Parse this field as a command line if it's a string or array
    pub fn as_command_line(&self) -> Option<super::command_line::CommandLine> {
        match self {
            FieldValue::Str(s) => Some(super::command_line::CommandLine::parse(s)),
            FieldValue::Array(arr) => {
                // Convert array to string arguments and parse
                let args: Vec<std::borrow::Cow<str>> = arr
                    .iter()
                    .filter_map(|item| match item {
                        FieldValue::Str(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect();

                if args.is_empty() {
                    None
                } else {
                    Some(super::command_line::CommandLine::from_args(args))
                }
            }
            _ => None,
        }
    }

    /// Parse this field as a command line, returning an error if not possible
    pub fn require_command_line(
        &self,
    ) -> Result<super::command_line::CommandLine, FieldConversionError> {
        self.as_command_line()
            .ok_or_else(|| FieldConversionError::UnsupportedOperation {
                operation: "command line parsing",
                field_type: format!("{:?}", self),
            })
    }
}
