pub mod builder;
pub mod command_line;
pub mod error;
pub mod field_map;
pub mod field_value;
pub mod from_impls;
pub mod getter;
pub mod ip;
pub mod operations;
pub mod specialized;
pub mod text;
pub mod time;
pub mod try_from_impls;

// Optional serde implementations (no derive) for Timestamp, Ip, FieldValue,
// and FieldMap.
#[cfg(feature = "serde")]
pub mod serde_impl;

#[cfg(test)]
mod command_line_tests;

// Re-export for compatibility
pub mod value {
    pub use super::error::*;
    pub use super::field_value::*;
    pub use super::getter::*;
}

pub use builder::ObjectBuilder;
pub use command_line::CommandLine;
pub use error::FieldConversionError;
pub use field_map::{FieldLookup, FieldMap, FieldMapIter};
pub use field_value::FieldValue;
pub use getter::FieldGetter;
pub use ip::{Ip, IpParseError};
pub use specialized::{Domain, Email, ParseError, Url};
pub use text::Text;
pub use time::{TimeParseError, Timestamp};
