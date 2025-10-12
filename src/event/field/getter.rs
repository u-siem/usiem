use super::error::FieldConversionError;
use super::field_value::FieldValue;
use super::ip::Ip;
use super::specialized::{Domain, Email, ParseError, Url};
use super::time::Timestamp;
use std::borrow::Cow;

/// Fluent field getter for improved ergonomics
#[derive(Debug)]
pub struct FieldGetter<'a> {
    pub(crate) field: Option<&'a FieldValue>,
    pub(crate) path: Cow<'a, str>,
}

impl<'a> FieldGetter<'a> {
    /// Extract as specific type
    pub fn extract<T>(&self) -> Result<T, FieldConversionError>
    where
        T: TryFrom<&'a FieldValue, Error = FieldConversionError>,
    {
        match self.field {
            Some(field) => field.try_into(),
            None => Err(FieldConversionError::IncompatibleType {
                from: "None",
                to: std::any::type_name::<T>(),
            }),
        }
    }

    /// Extract with default value
    pub fn extract_or<T>(&self, default: T) -> T
    where
        T: TryFrom<&'a FieldValue, Error = FieldConversionError>,
    {
        self.extract().unwrap_or(default)
    }

    /// Extract and expect success (panics on failure)
    pub fn expect<T>(&self, msg: &str) -> T
    where
        T: TryFrom<&'a FieldValue, Error = FieldConversionError>,
    {
        self.extract()
            .unwrap_or_else(|e| panic!("Field '{}' extraction failed: {}: {}", self.path, msg, e))
    }

    /// Convert to i64 with default
    pub fn as_i64(&self) -> Option<i64> {
        self.field?.as_i64()
    }

    /// Convert to i64 with default value
    pub fn as_i64_or(&self, default: i64) -> i64 {
        self.as_i64().unwrap_or(default)
    }

    /// Convert to u64 with default
    pub fn as_u64(&self) -> Option<u64> {
        self.field?.as_u64()
    }

    /// Convert to u64 with default value
    pub fn as_u64_or(&self, default: u64) -> u64 {
        self.as_u64().unwrap_or(default)
    }

    /// Convert to f64
    pub fn as_f64(&self) -> Option<f64> {
        self.field?.as_f64()
    }

    /// Convert to f64 with default value
    pub fn as_f64_or(&self, default: f64) -> f64 {
        self.as_f64().unwrap_or(default)
    }

    /// Convert to string
    pub fn as_str(&self) -> Option<&'a str> {
        self.field?.as_str()
    }

    /// Convert to string with default value
    pub fn as_str_or(&self, default: &'a str) -> &'a str {
        self.as_str().unwrap_or_else(move || default)
    }

    /// Convert to string with default value (returns owned String for temporary usage)
    pub fn as_str_or_owned(&self, default: &str) -> String {
        self.as_str().unwrap_or(default).to_owned()
    }

    // ===== String Utility Methods =====

    /// Check if string field contains the given substring (case sensitive)
    pub fn contains(&self, needle: &str) -> bool {
        self.field.map_or(false, |f| f.contains(needle))
    }

    /// Check if string field contains the given substring (case insensitive)
    pub fn contains_ignore_case(&self, needle: &str) -> bool {
        self.field.map_or(false, |f| f.contains_ignore_case(needle))
    }

    /// Check if string field starts with the given prefix (case sensitive)
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.field.map_or(false, |f| f.starts_with(prefix))
    }

    /// Check if string field starts with the given prefix (case insensitive)
    pub fn starts_with_ignore_case(&self, prefix: &str) -> bool {
        self.field
            .map_or(false, |f| f.starts_with_ignore_case(prefix))
    }

    /// Check if string field ends with the given suffix (case sensitive)
    pub fn ends_with(&self, suffix: &str) -> bool {
        self.field.map_or(false, |f| f.ends_with(suffix))
    }

    /// Check if string field ends with the given suffix (case insensitive)
    pub fn ends_with_ignore_case(&self, suffix: &str) -> bool {
        self.field
            .map_or(false, |f| f.ends_with_ignore_case(suffix))
    }

    /// Check if string field equals the given string (case sensitive)
    pub fn equals(&self, other: &str) -> bool {
        self.field.map_or(false, |f| f.equals(other))
    }

    /// Check if string field equals the given string (case insensitive)
    pub fn equals_ignore_case(&self, other: &str) -> bool {
        self.field.map_or(false, |f| f.equals_ignore_case(other))
    }

    /// Get the length of the string field (returns 0 for non-string fields or missing fields)
    pub fn len(&self) -> usize {
        self.field.map_or(0, |f| f.len())
    }

    /// Check if string field is empty (returns true for non-string fields or missing fields)
    pub fn is_empty(&self) -> bool {
        self.field.map_or(true, |f| f.is_empty())
    }

    /// Convert string field to lowercase (returns empty string for non-string or missing fields)
    pub fn to_lowercase(&self) -> String {
        self.field.map_or(String::new(), |f| f.to_lowercase())
    }

    /// Convert string field to uppercase (returns empty string for non-string or missing fields)
    pub fn to_uppercase(&self) -> String {
        self.field.map_or(String::new(), |f| f.to_uppercase())
    }

    /// Trim whitespace from string field (returns empty string for non-string or missing fields)
    pub fn trim(&self) -> &'a str {
        self.field.map_or("", |f| f.trim())
    }

    /// Split string field by delimiter (returns empty vec for non-string or missing fields)
    pub fn split(&self, delimiter: &'a str) -> Vec<&'a str> {
        self.field.map_or(Vec::new(), |f| f.split(delimiter))
    }

    /// Check if string field matches a pattern (returns false for non-string or missing fields)
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        self.field.map_or(false, |f| f.matches_pattern(pattern))
    }

    /// Convert to bool
    pub fn as_bool(&self) -> Option<bool> {
        self.field?.as_bool()
    }

    /// Convert to bool with default value
    pub fn as_bool_or(&self, default: bool) -> bool {
        self.as_bool().unwrap_or(default)
    }

    /// Convert to Timestamp
    pub fn as_time(&self) -> Option<Timestamp> {
        self.field?.as_time()
    }

    /// Convert to Ip
    pub fn as_ip(&self) -> Option<Ip> {
        self.field?.as_ip()
    }

    /// Check if field exists
    pub fn exists(&self) -> bool {
        self.field.is_some()
    }

    /// Check if field is missing
    pub fn is_missing(&self) -> bool {
        self.field.is_none()
    }

    // ===== Specialized Type Extraction =====

    /// Try to extract an email address from the string field
    pub fn as_email(&self) -> Result<Email<'_>, ParseError> {
        match self.field {
            Some(field) => field.as_email(),
            None => Err(ParseError::InvalidFormat("Field is missing")),
        }
    }

    /// Try to extract a domain from the string field
    pub fn as_domain(&self) -> Result<Domain<'_>, ParseError> {
        match self.field {
            Some(field) => field.as_domain(),
            None => Err(ParseError::InvalidFormat("Field is missing")),
        }
    }

    /// Try to extract a URL from the string field
    pub fn as_url(&self) -> Result<Url<'_>, ParseError> {
        match self.field {
            Some(field) => field.as_url(),
            None => Err(ParseError::InvalidFormat("Field is missing")),
        }
    }

    /// Get the raw field value
    pub fn raw(&self) -> Option<&'a FieldValue> {
        self.field
    }
}
