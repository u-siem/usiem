//! [`Schema`] → JSON Schema, gated behind the `json` feature.
//!
//! The immediate consumer is [`crate::mcp`]'s `inputSchema` for each MCP
//! tool (derived from an [`crate::processing::action::ActionDescriptor::params`]),
//! but this stands on its own — anything that needs a JSON Schema view of a
//! `Schema` can use it without pulling in the `mcp` feature.

use super::field::FieldValue;
use super::schema::{FieldConstraints, Schema, SchemaField, SchemaFieldType};
use serde_json::{Map, Value, json};

/// Renders a [`FieldValue`] as a plain JSON scalar for use inside a JSON
/// Schema `enum` — deliberately not [`FieldValue`]'s own tagged
/// `{"type": ..., "value": ...}` `Serialize` impl (which exists to
/// round-trip the full enum, `Object`/`Array` included, not to produce the
/// bare literal a JSON Schema `enum` entry needs to equal).
fn field_value_to_json_scalar(value: &FieldValue) -> Value {
    match value {
        FieldValue::Str(s) => json!(s.as_str()),
        FieldValue::Int(n) => json!(n),
        FieldValue::Uint(n) => json!(n),
        FieldValue::Float(n) => json!(n),
        FieldValue::Bool(b) => json!(b),
        FieldValue::Time(t) => json!(t.to_rfc3339()),
        FieldValue::Ip(ip) => json!(ip.to_string()),
        FieldValue::Bytes(_) | FieldValue::Object(_) | FieldValue::Array(_) => {
            // Not meaningful as a scalar `enum` entry; fall back to this
            // crate's own tagged form rather than silently dropping it.
            serde_json::to_value(value).unwrap_or(Value::Null)
        }
    }
}

impl Schema {
    /// Renders this schema as a JSON Schema (draft 2020-12-compatible)
    /// object: `{"type": "object", "properties": {...}, "required": [...]}`.
    ///
    /// Notes on the mapping:
    /// - [`SchemaFieldType::Uint`] has no dedicated JSON Schema type;
    ///   it's `{"type": "integer", "minimum": 0}` (a lower bound of `0`
    ///   merged with any explicit [`FieldConstraints::min_value`]).
    /// - [`SchemaFieldType::Ip`] deliberately renders as a plain
    ///   `{"type": "string"}` rather than JSON Schema's `format: "ipv4"`:
    ///   that format only covers IPv4, and this crate's [`crate::event::field::Ip`]
    ///   covers both v4 and v6 — a single `format` value would reject valid
    ///   input either way. Emit-side documentation only; nothing in this
    ///   crate enforces `format` on the way back in either.
    /// - [`SchemaFieldType::Bytes`] renders as `{"type": "string",
    ///   "contentEncoding": "base64"}` — this crate has no built-in
    ///   base64 (de)serialization for it; that's the caller's job.
    /// - [`SchemaFieldType::Any`] renders as `{}` (accepts anything).
    pub fn to_json_schema(&self) -> Value {
        let mut properties = Map::new();
        for (name, field) in &self.fields {
            properties.insert(name.clone(), field_to_json_schema(field));
        }
        json!({
            "type": "object",
            "properties": Value::Object(properties),
            "required": self.required_fields,
        })
    }
}

fn field_to_json_schema(field: &SchemaField) -> Value {
    let mut schema = field_type_to_json_schema(&field.field_type);
    if let Value::Object(obj) = &mut schema {
        if let Some(description) = &field.description {
            obj.insert("description".to_string(), json!(description));
        }
        apply_constraints(obj, &field.constraints);
    }
    schema
}

fn apply_constraints(obj: &mut Map<String, Value>, constraints: &FieldConstraints) {
    if let Some(min) = constraints.min_value {
        obj.insert("minimum".to_string(), json!(min));
    }
    if let Some(max) = constraints.max_value {
        obj.insert("maximum".to_string(), json!(max));
    }
    if let Some(min_len) = constraints.min_length {
        obj.insert("minLength".to_string(), json!(min_len));
    }
    if let Some(max_len) = constraints.max_length {
        obj.insert("maxLength".to_string(), json!(max_len));
    }
    if let Some(pattern) = &constraints.pattern {
        obj.insert("pattern".to_string(), json!(pattern));
    }
    if let Some(allowed) = &constraints.allowed_values {
        let values: Vec<Value> = allowed.iter().map(field_value_to_json_scalar).collect();
        obj.insert("enum".to_string(), Value::Array(values));
    }
}

fn field_type_to_json_schema(ty: &SchemaFieldType) -> Value {
    match ty {
        SchemaFieldType::Str => json!({"type": "string"}),
        SchemaFieldType::Int => json!({"type": "integer"}),
        SchemaFieldType::Uint => json!({"type": "integer", "minimum": 0}),
        SchemaFieldType::Float => json!({"type": "number"}),
        SchemaFieldType::Bool => json!({"type": "boolean"}),
        SchemaFieldType::Bytes => json!({"type": "string", "contentEncoding": "base64"}),
        SchemaFieldType::Time => json!({"type": "string", "format": "date-time"}),
        SchemaFieldType::Ip => json!({"type": "string"}),
        SchemaFieldType::Object(nested) => nested.to_json_schema(),
        SchemaFieldType::Array(element) => {
            json!({"type": "array", "items": field_type_to_json_schema(element)})
        }
        SchemaFieldType::Union(members) => {
            let variants: Vec<Value> = members.iter().map(field_type_to_json_schema).collect();
            json!({"oneOf": variants})
        }
        SchemaFieldType::Any => json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::FieldValue;

    #[test]
    fn test_simple_schema_to_json_schema() {
        let mut schema = Schema::new("block_ip".to_string(), "1".to_string());
        schema.add_field(
            "ip",
            Schema::ip_field()
                .required()
                .description("the IP to block")
                .build(),
        );
        schema.add_field("ttl_secs", Schema::uint_field().build());

        let json = schema.to_json_schema();
        assert_eq!(json["type"], "object");
        assert_eq!(json["properties"]["ip"]["type"], "string");
        assert_eq!(json["properties"]["ip"]["description"], "the IP to block");
        assert_eq!(json["properties"]["ttl_secs"]["type"], "integer");
        assert_eq!(json["properties"]["ttl_secs"]["minimum"], 0);
        assert_eq!(json["required"], json!(["ip"]));
    }

    #[test]
    fn test_constraints_and_enum_are_rendered() {
        let mut schema = Schema::new("set_log_level".to_string(), "1".to_string());
        schema.add_field(
            "level",
            Schema::str_field()
                .required()
                .allowed_values([FieldValue::str("debug"), FieldValue::str("info")])
                .min_length(1)
                .max_length(10)
                .build(),
        );

        let json = schema.to_json_schema();
        assert_eq!(json["properties"]["level"]["minLength"], 1);
        assert_eq!(json["properties"]["level"]["maxLength"], 10);
        assert_eq!(
            json["properties"]["level"]["enum"],
            json!(["debug", "info"])
        );
    }

    #[test]
    fn test_array_and_nested_object_fields() {
        let mut nested = Schema::new("target".to_string(), "1".to_string());
        nested.add_field("host", Schema::str_field().required().build());

        let mut schema = Schema::new("isolate_host".to_string(), "1".to_string());
        schema.add_field("tags", Schema::array_field(SchemaFieldType::Str).build());
        schema.add_field("target", Schema::object_field(nested).build());

        let json = schema.to_json_schema();
        assert_eq!(json["properties"]["tags"]["type"], "array");
        assert_eq!(json["properties"]["tags"]["items"]["type"], "string");
        assert_eq!(json["properties"]["target"]["type"], "object");
        assert_eq!(
            json["properties"]["target"]["properties"]["host"]["type"],
            "string"
        );
    }
}
