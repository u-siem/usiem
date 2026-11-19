pub mod core;
pub mod field;
pub mod fields;
pub mod hash;
pub mod json;
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

pub use core::{Event, EventId, RawData};
pub use field::{FieldMap, FieldValue, Ip, ObjectBuilder, Timestamp};

/// The old name of [`Event`], from when `Event` named the field-object
/// builder (now only [`ObjectBuilder`]).
#[deprecated(note = "use `usiem::event::Event`")]
pub type CoreEvent = Event;
pub use json::JsonValue;
pub use origin::Origin;
pub use raw::RawEvent;
pub use schema::{
    FieldConstraints, Schema, SchemaError, SchemaField, SchemaFieldBuilder, SchemaFieldType,
    SchemaMetadata,
};
