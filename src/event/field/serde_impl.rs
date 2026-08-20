//! Hand-written (no derive) `Serialize`/`Deserialize` for the field-value
//! system ([`Timestamp`], [`Ip`], [`FieldValue`], [`FieldMap`]), following
//! the tagged `{"type": ..., "value": ...}` convention already used for
//! [`crate::event::Origin`]/[`crate::event::RawData`] in `event::core_serde`
//! — except [`FieldMap`], which serializes as a plain JSON object (it's
//! already a named bag of fields, not a tagged union, so it needs no `type`
//! tag of its own). A derive can't be used for `FieldMap` regardless: its
//! backing store is a `SmallVec` of `(Text, FieldValue)` pairs, and a
//! derived `Serialize` would render that as a JSON *array* of `[key,
//! value]` pairs, not the object shape this type actually represents.
//!
//! `FieldValue::Str`/keys are otherwise treated opaquely via `.as_ref()`/
//! `String` — except `FieldValue::Object`'s `HashMap<Text, FieldValue>`,
//! which is handed to `serde` as a whole (`tagged(serializer, "object", v)`)
//! and therefore needs `Text: Serialize`/`Deserialize` directly, since
//! `HashMap`'s own impls require their key type to serialize too. That's
//! why `compact_str`'s own `"serde"` Cargo feature is enabled (see
//! `Cargo.toml`) rather than being skippable.

use super::field_map::FieldMap;
use super::field_value::FieldValue;
use super::ip::Ip;
use super::text::Text;
use super::time::Timestamp;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Serializes as a bare `i64` (nanoseconds since the Unix epoch) rather than an
/// RFC3339 string, so the round trip is exact and never needs a re-parse.
impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        i64::deserialize(deserializer).map(Timestamp::from_nanos)
    }
}

// Serialized as its string form (e.g. "127.0.0.1", "::1"), matching how
// `Origin::Ip` already embeds an address in `event::core_serde`.
impl Serialize for Ip {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ip {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ip::from_str(&s).map_err(de::Error::custom)
    }
}

const FIELD_VALUE_VARIANTS: &[&str] = &[
    "str", "int", "uint", "float", "bool", "bytes", "time", "ip", "object", "array",
];

impl Serialize for FieldValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        fn tagged<S: Serializer, T: Serialize + ?Sized>(
            serializer: S,
            tag: &str,
            value: &T,
        ) -> Result<S::Ok, S::Error> {
            let mut state = serializer.serialize_struct("FieldValue", 2)?;
            state.serialize_field("type", tag)?;
            state.serialize_field("value", value)?;
            state.end()
        }

        match self {
            FieldValue::Str(s) => tagged(serializer, "str", s),
            FieldValue::Int(v) => tagged(serializer, "int", v),
            FieldValue::Uint(v) => tagged(serializer, "uint", v),
            FieldValue::Float(v) => tagged(serializer, "float", v),
            FieldValue::Bool(v) => tagged(serializer, "bool", v),
            FieldValue::Bytes(v) => tagged(serializer, "bytes", v),
            FieldValue::Time(v) => tagged(serializer, "time", v),
            FieldValue::Ip(v) => tagged(serializer, "ip", v),
            FieldValue::Object(v) => tagged(serializer, "object", v),
            FieldValue::Array(v) => tagged(serializer, "array", v),
        }
    }
}

impl<'de> Deserialize<'de> for FieldValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldValueVisitor;

        impl<'de> Visitor<'de> for FieldValueVisitor {
            type Value = FieldValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a FieldValue struct with type and value fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<FieldValue, A::Error>
            where
                A: MapAccess<'de>,
            {
                // `value`'s Rust type depends on `type`, so this visitor requires
                // "type" to appear before "value" in the map (always true for
                // data this crate's own `Serialize` impl produced, since it
                // writes "type" first).
                let mut field_type: Option<String> = None;
                let mut result: Option<FieldValue> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => field_type = Some(map.next_value()?),
                        "value" => {
                            let tag = field_type.as_deref().ok_or_else(|| {
                                de::Error::custom(
                                    "'type' must appear before 'value' in a serialized FieldValue",
                                )
                            })?;
                            result = Some(match tag {
                                "str" => FieldValue::Str(Text::from(map.next_value::<String>()?)),
                                "int" => FieldValue::Int(map.next_value()?),
                                "uint" => FieldValue::Uint(map.next_value()?),
                                "float" => FieldValue::Float(map.next_value()?),
                                "bool" => FieldValue::Bool(map.next_value()?),
                                "bytes" => FieldValue::Bytes(map.next_value()?),
                                "time" => FieldValue::Time(map.next_value()?),
                                "ip" => FieldValue::Ip(map.next_value()?),
                                "object" => FieldValue::Object(
                                    map.next_value::<HashMap<Text, FieldValue>>()?,
                                ),
                                "array" => FieldValue::Array(map.next_value::<Vec<FieldValue>>()?),
                                other => {
                                    return Err(de::Error::unknown_variant(
                                        other,
                                        FIELD_VALUE_VARIANTS,
                                    ));
                                }
                            });
                        }
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }

                result.ok_or_else(|| de::Error::missing_field("value"))
            }
        }

        deserializer.deserialize_struct("FieldValue", &["type", "value"], FieldValueVisitor)
    }
}

/// Serializes as a plain JSON object — one entry per field, each value
/// using [`FieldValue`]'s own tagged serialization above. See the module
/// doc for why this can't be derived.
impl Serialize for FieldMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self.iter() {
            let key: &str = key.as_ref();
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for FieldMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldMapVisitor;

        impl<'de> Visitor<'de> for FieldMapVisitor {
            type Value = FieldMap;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map of field names to values")
            }

            fn visit_map<A>(self, mut map: A) -> Result<FieldMap, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut result = FieldMap::new();
                while let Some((key, value)) = map.next_entry::<String, FieldValue>()? {
                    result.insert(key, value);
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(FieldMapVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de>>(value: &T) -> T {
        let json = serde_json::to_string(value).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn timestamp_roundtrips_as_bare_number() {
        let ts = Timestamp::from_nanos(1_700_000_000_123_456_789);
        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, "1700000000123456789");
        assert_eq!(roundtrip(&ts), ts);
    }

    #[test]
    fn ip_v4_and_v6_roundtrip() {
        let v4 = Ip::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v6 = Ip::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(serde_json::to_string(&v4).unwrap(), "\"192.168.1.1\"");
        assert_eq!(roundtrip(&v4), v4);
        assert_eq!(roundtrip(&v6), v6);
    }

    // FieldValue's own PartialEq treats Int/Uint/Float as interchangeable when
    // numerically equal, so a plain `assert_eq!` wouldn't catch a bug that
    // deserialized every numeric tag back as the same variant. These tests
    // check `type_name()` explicitly wherever that ambiguity exists.
    #[test]
    fn field_value_numeric_variants_preserve_their_exact_type() {
        let int_val = FieldValue::Int(5);
        let uint_val = FieldValue::Uint(5);
        let float_val = FieldValue::Float(5.0);

        assert_eq!(roundtrip(&int_val).type_name(), "Int");
        assert_eq!(roundtrip(&uint_val).type_name(), "Uint");
        assert_eq!(roundtrip(&float_val).type_name(), "Float");
    }

    #[test]
    fn field_value_scalar_variants_roundtrip() {
        assert_eq!(
            roundtrip(&FieldValue::str("hello")),
            FieldValue::str("hello")
        );
        assert_eq!(roundtrip(&FieldValue::Bool(true)), FieldValue::Bool(true));
        assert_eq!(
            roundtrip(&FieldValue::Bytes(vec![0, 1, 2, 255])),
            FieldValue::Bytes(vec![0, 1, 2, 255])
        );
        assert_eq!(
            roundtrip(&FieldValue::Time(Timestamp::from_secs(1_700_000_000))),
            FieldValue::Time(Timestamp::from_secs(1_700_000_000))
        );
        let ip = FieldValue::Ip(Ip::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(roundtrip(&ip), ip);
    }

    #[test]
    fn field_value_nested_object_and_array_roundtrip() {
        let mut inner = HashMap::new();
        inner.insert(Text::from("nested_int"), FieldValue::Int(-1));
        inner.insert(
            Text::from("nested_arr"),
            FieldValue::Array(vec![FieldValue::str("a"), FieldValue::Bool(false)]),
        );

        let value = FieldValue::Object(inner);
        let restored = roundtrip(&value);
        assert_eq!(restored, value);

        // Confirm the nested array element types survived, not just the map shape.
        match restored.get_nested_field("nested_arr") {
            Some(FieldValue::Array(arr)) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0].type_name(), "Str");
                assert_eq!(arr[1].type_name(), "Bool");
            }
            other => panic!("expected a nested array, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_tag_is_rejected() {
        let err = serde_json::from_str::<FieldValue>(r#"{"type":"nope","value":1}"#).unwrap_err();
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn field_map_roundtrips() {
        let mut map = FieldMap::new();
        map.insert("ip", FieldValue::str("203.0.113.5"));
        map.insert("count", FieldValue::uint(3));

        let restored = roundtrip(&map);
        assert_eq!(restored.get("ip"), Some(&FieldValue::str("203.0.113.5")));
        assert_eq!(restored.get("count"), Some(&FieldValue::uint(3)));
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn field_map_serializes_as_a_plain_object_not_an_array_of_pairs() {
        let mut map = FieldMap::new();
        map.insert("ip", FieldValue::str("203.0.113.5"));

        let value = serde_json::to_value(&map).unwrap();
        assert!(value.is_object(), "expected a JSON object, got: {value:?}");
    }

    #[test]
    fn field_map_deserializes_from_a_plain_json_object() {
        let map: FieldMap =
            serde_json::from_str(r#"{"ip":{"type":"str","value":"203.0.113.5"}}"#).unwrap();
        assert_eq!(map.get("ip"), Some(&FieldValue::str("203.0.113.5")));
    }
}
