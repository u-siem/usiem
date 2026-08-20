use crate::event::Origin;
use crate::event::core::{Event, RawData};
use crate::event::field::{FieldValue, Ip, Timestamp};
use crate::event::json::JsonValue;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

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
            Origin::File(path) => {
                let mut state = serializer.serialize_struct("Origin", 2)?;
                state.serialize_field("type", "file")?;
                state.serialize_field("value", path)?;
                state.end()
            }
            Origin::Container { id, name, image } => {
                let mut state = serializer.serialize_struct("Origin", 4)?;
                state.serialize_field("type", "container")?;
                state.serialize_field("id", id)?;
                state.serialize_field("name", name)?;
                state.serialize_field("image", image)?;
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
                let mut id: Option<String> = None;
                let mut name: Option<String> = None;
                let mut image: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => origin_type = Some(map.next_value()?),
                        "value" => value = Some(map.next_value()?),
                        "id" => id = Some(map.next_value()?),
                        "name" => name = map.next_value()?,
                        "image" => image = map.next_value()?,
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let origin_type = origin_type.ok_or_else(|| de::Error::missing_field("type"))?;

                match origin_type.as_str() {
                    "ip" => {
                        let value = value.ok_or_else(|| de::Error::missing_field("value"))?;
                        let ip = Ip::from_str(&value)
                            .map_err(|_| de::Error::custom("Invalid IP address format"))?;
                        Ok(Origin::Ip(ip))
                    }
                    "hostname" => Ok(Origin::Hostname(
                        value.ok_or_else(|| de::Error::missing_field("value"))?,
                    )),
                    "collector" => Ok(Origin::Collector(
                        value.ok_or_else(|| de::Error::missing_field("value"))?,
                    )),
                    "file" => Ok(Origin::File(
                        value.ok_or_else(|| de::Error::missing_field("value"))?,
                    )),
                    "container" => Ok(Origin::Container {
                        id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                        name,
                        image,
                    }),
                    _ => Err(de::Error::unknown_variant(
                        &origin_type,
                        &["ip", "hostname", "collector", "file", "container"],
                    )),
                }
            }
        }

        deserializer.deserialize_struct(
            "Origin",
            &["type", "value", "id", "name", "image"],
            OriginVisitor,
        )
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

// Serde implementation for Event, as a plain field-for-field struct (unlike the
// tagged-enum encodings above) since Event has only one shape. Built on top of
// Origin/RawData's impls here and FieldValue/Timestamp's impls in
// `event::field::serde_impl`. `EventId` is deliberately not part of the wire
// format — it's derived from the other fields via `Event::id()`, not stored.
impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Event", 5)?;
        state.serialize_field("arrival_time", &self.arrival_time)?;
        state.serialize_field("original_time", &self.original_time)?;
        state.serialize_field("origin", &self.origin)?;
        state.serialize_field("raw_data", &self.raw_data)?;
        state.serialize_field("fields", &self.fields)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct EventVisitor;

        impl<'de> Visitor<'de> for EventVisitor {
            type Value = Event;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "an Event struct with arrival_time, original_time, origin, raw_data, and fields",
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<Event, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut arrival_time: Option<Timestamp> = None;
                let mut original_time: Option<Timestamp> = None;
                let mut origin: Option<Origin> = None;
                let mut raw_data: Option<RawData> = None;
                let mut fields: Option<HashMap<String, FieldValue>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "arrival_time" => arrival_time = Some(map.next_value()?),
                        "original_time" => original_time = Some(map.next_value()?),
                        "origin" => origin = Some(map.next_value()?),
                        "raw_data" => raw_data = Some(map.next_value()?),
                        "fields" => fields = Some(map.next_value()?),
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(Event {
                    arrival_time: arrival_time
                        .ok_or_else(|| de::Error::missing_field("arrival_time"))?,
                    original_time: original_time
                        .ok_or_else(|| de::Error::missing_field("original_time"))?,
                    origin: origin.ok_or_else(|| de::Error::missing_field("origin"))?,
                    raw_data: raw_data.ok_or_else(|| de::Error::missing_field("raw_data"))?,
                    fields: fields.ok_or_else(|| de::Error::missing_field("fields"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "Event",
            &[
                "arrival_time",
                "original_time",
                "origin",
                "raw_data",
                "fields",
            ],
            EventVisitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::FieldValue;
    use std::net::Ipv4Addr;

    #[test]
    fn event_roundtrips_through_json_with_nested_fields() {
        let mut event = Event::new(
            Timestamp::from_secs(1_700_000_100),
            Timestamp::from_secs(1_700_000_000),
            Origin::from_ip(Ip::V4(Ipv4Addr::new(10, 0, 0, 1))),
            RawData::from_text("raw log line"),
        );
        event.add_field("event_type".to_string(), FieldValue::str("authentication"));
        event.add_field("severity".to_string(), FieldValue::Int(8));
        event.add_field(
            "tags".to_string(),
            FieldValue::Array(vec![FieldValue::str("suspicious"), FieldValue::Bool(true)]),
        );

        let json = serde_json::to_string(&event).unwrap();
        let restored: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, event);
        assert_eq!(
            restored.get_field("event_type"),
            Some(&FieldValue::str("authentication"))
        );
    }
}
