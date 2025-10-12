use crate::event::core::{Event, Origin, RawData};
use crate::event::field::{FieldValue, Ip, Timestamp};
use crate::event::json::JsonValue;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;

// Serde implementation for Origin
impl Serialize for Origin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        match self {
            Origin::Ip(ip) => {
                let mut state = serializer.serialize_struct("Origin", 2)?;
                state.serialize_field("type", "ip")?;
                state.serialize_field("value", &ip.to_string())?;
                state.end()
            }
            Origin::Hostname(hostname) => {
                let mut state = serializer.serialize_struct("Origin", 2)?;
                state.serialize_field("type", "hostname")?;
                state.serialize_field("value", hostname)?;
                state.end()
            }
            Origin::Collector(collector_id) => {
                let mut state = serializer.serialize_struct("Origin", 2)?;
                state.serialize_field("type", "collector")?;
                state.serialize_field("value", collector_id)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct OriginVisitor;

        impl<'de> Visitor<'de> for OriginVisitor {
            type Value = Origin;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an Origin struct with type and value fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Origin, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut origin_type: Option<String> = None;
                let mut value: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => origin_type = Some(map.next_value()?),
                        "value" => value = Some(map.next_value()?),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let origin_type = origin_type.ok_or_else(|| de::Error::missing_field("type"))?;
                let value = value.ok_or_else(|| de::Error::missing_field("value"))?;

                match origin_type.as_str() {
                    "ip" => {
                        let ip = Ip::from_str(&value)
                            .map_err(|_| de::Error::custom("Invalid IP address format"))?;
                        Ok(Origin::Ip(ip))
                    }
                    "hostname" => Ok(Origin::Hostname(value)),
                    "collector" => Ok(Origin::Collector(value)),
                    _ => Err(de::Error::unknown_variant(
                        &origin_type,
                        &["ip", "hostname", "collector"],
                    )),
                }
            }
        }

        deserializer.deserialize_struct("Origin", &["type", "value"], OriginVisitor)
    }
}

// Serde implementation for RawData
impl Serialize for RawData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        match self {
            RawData::Text(text) => {
                let mut state = serializer.serialize_struct("RawData", 2)?;
                state.serialize_field("type", "text")?;
                state.serialize_field("data", text)?;
                state.end()
            }
            RawData::Json(json) => {
                let mut state = serializer.serialize_struct("RawData", 2)?;
                state.serialize_field("type", "json")?;
                state.serialize_field("data", json)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RawData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct RawDataVisitor;

        impl<'de> Visitor<'de> for RawDataVisitor {
            type Value = RawData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a RawData struct with type and data fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<RawData, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut data_type: Option<String> = None;
                let mut text_data: Option<String> = None;
                let mut json_data: Option<JsonValue> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => data_type = Some(map.next_value()?),
                        "data" => {
                            if let Some(ref dt) = data_type {
                                match dt.as_str() {
                                    "text" => text_data = Some(map.next_value()?),
                                    "json" => json_data = Some(map.next_value()?),
                                    _ => {
                                        map.next_value::<serde::de::IgnoredAny>()?;
                                    }
                                }
                            } else {
                                // We don't know the type yet, try to deserialize as JsonValue first
                                json_data = Some(map.next_value()?);
                            }
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let data_type = data_type.ok_or_else(|| de::Error::missing_field("type"))?;

                match data_type.as_str() {
                    "text" => {
                        let text = text_data.ok_or_else(|| de::Error::missing_field("data"))?;
                        Ok(RawData::Text(text))
                    }
                    "json" => {
                        let json = json_data.ok_or_else(|| de::Error::missing_field("data"))?;
                        Ok(RawData::Json(json))
                    }
                    _ => Err(de::Error::unknown_variant(&data_type, &["text", "json"])),
                }
            }
        }

        deserializer.deserialize_struct("RawData", &["type", "data"], RawDataVisitor)
    }
}

// Note: Event serde implementation would require FieldValue and Timestamp to have serde support
// This is left as a future enhancement when those types get their own serde implementations
