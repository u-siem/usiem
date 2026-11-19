pub mod core;
pub mod field;
pub mod fields;
pub mod hash;
pub mod json;
pub mod metadata;
pub mod origin;
pub mod raw;
pub mod schema;

// Optional serde implementations (no derive)
#[cfg(feature = "serde")]
pub mod serde_impl;

#[cfg(feature = "json")]
pub mod json_interop;

#[cfg(feature = "json")]
pub mod json_schema;

#[cfg(feature = "serde")]
pub mod core_serde;

pub use core::{Event as CoreEvent, EventId, RawData};
pub use field::{Event, EventBuilder, FieldMap, FieldValue, Ip, ObjectBuilder, Timestamp};
pub use json::JsonValue;
pub use origin::Origin;
pub use raw::RawEvent;
pub use schema::{
    FieldConstraints, Schema, SchemaError, SchemaField, SchemaFieldBuilder, SchemaFieldType,
    SchemaMetadata,
};
