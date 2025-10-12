use crate::event::json::JsonValue;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;

// Serde implementation for JsonValue
impl Serialize for JsonValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            JsonValue::Null => serializer.serialize_unit(),
            JsonValue::Bool(b) => serializer.serialize_bool(*b),
            JsonValue::Number(n) => {
                // Try to serialize as integer if it's a whole number
                if n.fract() == 0.0
                    && n.is_finite()
                    && *n >= i64::MIN as f64
                    && *n <= i64::MAX as f64
                {
                    serializer.serialize_i64(*n as i64)
                } else {
                    serializer.serialize_f64(*n)
                }
            }
            JsonValue::String(s) => serializer.serialize_str(s),
            JsonValue::Array(arr) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(arr.len()))?;
                for item in arr {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            JsonValue::Object(obj) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(obj.len()))?;
                for (key, value) in obj {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct JsonValueVisitor;

        impl<'de> Visitor<'de> for JsonValueVisitor {
            type Value = JsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any valid JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::Number(value as f64))
            }

            fn visit_u64<E>(self, value: u64) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::Number(value as f64))
            }

            fn visit_f64<E>(self, value: f64) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::Number(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::String(value.to_string()))
            }

            fn visit_string<E>(self, value: String) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::String(value))
            }

            fn visit_unit<E>(self) -> Result<JsonValue, E>
            where
                E: de::Error,
            {
                Ok(JsonValue::Null)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<JsonValue, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(item) = seq.next_element()? {
                    vec.push(item);
                }
                Ok(JsonValue::Array(vec))
            }

            fn visit_map<A>(self, mut map: A) -> Result<JsonValue, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut obj = HashMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    obj.insert(key, value);
                }
                Ok(JsonValue::Object(obj))
            }
        }

        deserializer.deserialize_any(JsonValueVisitor)
    }
}
