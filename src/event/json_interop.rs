use crate::event::field::{FieldValue, Text};
use crate::event::json::JsonValue;

impl FieldValue {
    /// Recursively converts a `serde_json::Value` into a [`FieldValue`],
    /// preserving nested objects/arrays as `FieldValue::Object`/`Array`
    /// instead of stringifying them — `FieldValue` supports arbitrary nesting
    /// natively, so there's no need to flatten. JSON `null` has no
    /// `FieldValue` equivalent (the type has no `Null` variant, only "field
    /// absent"), so `null` itself returns `None`, and null-valued object
    /// fields and null array elements are dropped rather than becoming the
    /// literal string `"null"`.
    ///
    /// Integers that fit in `i64` become `Int`, larger positive ones `Uint`,
    /// everything else `Float`.
    ///
    /// ```
    /// use usiem::event::FieldValue;
    ///
    /// let value = FieldValue::from_json(serde_json::json!([443, "a", null])).unwrap();
    /// assert_eq!(
    ///     value,
    ///     FieldValue::Array(vec![FieldValue::Int(443), FieldValue::from("a")])
    /// );
    /// assert_eq!(FieldValue::from_json(serde_json::Value::Null), None);
    /// ```
    pub fn from_json(value: serde_json::Value) -> Option<FieldValue> {
        match value {
            serde_json::Value::Null => None,
            serde_json::Value::Bool(b) => Some(FieldValue::Bool(b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Some(FieldValue::Int(i))
                } else if let Some(u) = n.as_u64() {
                    Some(FieldValue::Uint(u))
                } else {
                    n.as_f64().map(FieldValue::Float)
                }
            }
            serde_json::Value::String(s) => Some(FieldValue::Str(Text::from(s))),
            serde_json::Value::Array(arr) => Some(FieldValue::Array(
                arr.into_iter().filter_map(FieldValue::from_json).collect(),
            )),
            serde_json::Value::Object(map) => Some(FieldValue::Object(
                map.into_iter()
                    .filter_map(|(k, v)| FieldValue::from_json(v).map(|fv| (Text::from(k), fv)))
                    .collect(),
            )),
        }
    }
}

// serde_json interop implementations
impl From<serde_json::Value> for JsonValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => JsonValue::Null,
            serde_json::Value::Bool(b) => JsonValue::Bool(b),
            serde_json::Value::Number(n) => JsonValue::Number(n.as_f64().unwrap_or(0.0)),
            serde_json::Value::String(s) => JsonValue::String(s),
            serde_json::Value::Array(arr) => {
                JsonValue::Array(arr.into_iter().map(JsonValue::from).collect())
            }
            serde_json::Value::Object(obj) => JsonValue::Object(
                obj.into_iter()
                    .map(|(k, v)| (k, JsonValue::from(v)))
                    .collect(),
            ),
        }
    }
}

impl From<JsonValue> for serde_json::Value {
    fn from(value: JsonValue) -> Self {
        match value {
            JsonValue::Null => serde_json::Value::Null,
            JsonValue::Bool(b) => serde_json::Value::Bool(b),
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && n.is_finite() {
                    serde_json::Value::Number(serde_json::Number::from(n as i64))
                } else {
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(n)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    )
                }
            }
            JsonValue::String(s) => serde_json::Value::String(s),
            JsonValue::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(serde_json::Value::from).collect())
            }
            JsonValue::Object(obj) => serde_json::Value::Object(
                obj.into_iter()
                    .map(|(k, v)| (k, serde_json::Value::from(v)))
                    .collect(),
            ),
        }
    }
}
