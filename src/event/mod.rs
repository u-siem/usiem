pub mod core;
pub mod field;
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

#[cfg(feature = "serde")]
pub mod core_serde;

pub use core::{Event as CoreEvent, RawData};
pub use field::{Event, EventBuilder, FieldValue, Ip, ObjectBuilder, Timestamp};
pub use json::JsonValue;
pub use origin::Origin;
pub use raw::RawEvent;
pub use schema::{
    FieldConstraints, Schema, SchemaField, SchemaFieldBuilder, SchemaFieldType, SchemaMetadata,
};
