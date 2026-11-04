use super::core::Event;
use super::field::{FieldLookup, FieldMap, FieldValue, Timestamp};
use regex::Regex;
use std::collections::HashMap;

/// Field type definitions for schema validation
#[derive(Debug, Clone)]
pub enum SchemaFieldType {
    Str,
    Int,
    Uint,
    Float,
    Bool,
    Bytes,
    Time,
    Ip,
    Object(Box<Schema>),
    Array(Box<SchemaFieldType>),
    Union(Vec<SchemaFieldType>),
    Any,
}

impl PartialEq for SchemaFieldType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SchemaFieldType::Str, SchemaFieldType::Str) => true,
            (SchemaFieldType::Int, SchemaFieldType::Int) => true,
            (SchemaFieldType::Uint, SchemaFieldType::Uint) => true,
            (SchemaFieldType::Float, SchemaFieldType::Float) => true,
            (SchemaFieldType::Bool, SchemaFieldType::Bool) => true,
            (SchemaFieldType::Bytes, SchemaFieldType::Bytes) => true,
            (SchemaFieldType::Time, SchemaFieldType::Time) => true,
            (SchemaFieldType::Ip, SchemaFieldType::Ip) => true,
            (SchemaFieldType::Any, SchemaFieldType::Any) => true,
            (SchemaFieldType::Array(a), SchemaFieldType::Array(b)) => a == b,
            (SchemaFieldType::Union(a), SchemaFieldType::Union(b)) => a == b,
            // Skip object comparison for now
            _ => false,
        }
    }
}

/// Field definition in a schema
#[derive(Debug, Clone)]
pub struct SchemaField {
    /// Field type
    pub field_type: SchemaFieldType,

    /// Whether this field is required
    pub required: bool,

    /// Default value if not present
    pub default_value: Option<FieldValue>,

    /// Field description
    pub description: Option<String>,

    /// Validation constraints
    pub constraints: FieldConstraints,

    /// Field aliases (alternative names)
    pub aliases: Vec<String>,

    /// Whether to normalize this field name
    pub normalize: bool,
}

/// Validation constraints for fields
#[derive(Debug, Clone, Default)]
pub struct FieldConstraints {
    /// Minimum value for numeric fields
    pub min_value: Option<f64>,

    /// Maximum value for numeric fields
    pub max_value: Option<f64>,

    /// Minimum length for string/array fields
    pub min_length: Option<usize>,

    /// Maximum length for string/array fields
    pub max_length: Option<usize>,

    /// Regular expression pattern for string fields
    pub pattern: Option<String>,

    /// Allowed values (enum)
    pub allowed_values: Option<Vec<FieldValue>>,
}

/// Event schema definition
#[derive(Debug, Clone)]
pub struct Schema {
    /// Schema name/identifier
    pub name: String,

    /// Schema version
    pub version: String,

    /// Field definitions
    pub fields: HashMap<String, SchemaField>,

    /// Required fields (for quick lookup)
    pub required_fields: Vec<String>,

    /// Field normalization mappings (alias -> canonical name)
    pub field_mappings: HashMap<String, String>,

    /// Schema metadata
    pub metadata: SchemaMetadata,
}

#[derive(Debug, Clone)]
pub struct SchemaMetadata {
    /// Schema description
    pub description: Option<String>,

    /// Schema tags for categorization
    pub tags: Vec<String>,

    /// Schema author
    pub author: Option<String>,

    /// When the schema was created
    pub created: Option<Timestamp>,

    /// When the schema was last modified
    pub modified: Option<Timestamp>,
}

impl Schema {
    /// Create a new schema
    pub fn new<S: Into<String>>(name: S, version: S) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            fields: HashMap::new(),
            required_fields: Vec::new(),
            field_mappings: HashMap::new(),
            metadata: SchemaMetadata {
                description: None,
                tags: Vec::new(),
                author: None,
                created: None,
                modified: None,
            },
        }
    }

    /// Add a field to the schema
    pub fn add_field<S: Into<String>>(&mut self, name: S, field: SchemaField) -> &mut Self {
        let field_name = name.into();

        // Add to required fields list if required
        if field.required && !self.required_fields.contains(&field_name) {
            self.required_fields.push(field_name.clone());
        }

        // Add field aliases to mappings
        for alias in &field.aliases {
            self.field_mappings
                .insert(alias.clone(), field_name.clone());
        }

        self.fields.insert(field_name, field);
        self
    }

    /// Create a string field
    pub fn str_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Str)
    }

    /// Create an integer field
    pub fn int_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Int)
    }

    /// Create an unsigned integer field
    pub fn uint_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Uint)
    }

    /// Create a float field
    pub fn float_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Float)
    }

    /// Create a boolean field
    pub fn bool_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Bool)
    }

    /// Create a time field
    pub fn time_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Time)
    }

    /// Create an IP field
    pub fn ip_field() -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Ip)
    }

    /// Create an object field
    pub fn object_field(schema: Schema) -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Object(Box::new(schema)))
    }

    /// Create an array field
    pub fn array_field(element_type: SchemaFieldType) -> SchemaFieldBuilder {
        SchemaFieldBuilder::new(SchemaFieldType::Array(Box::new(element_type)))
    }

    /// Validates `event`'s fields against this schema.
    ///
    /// Every violation is collected rather than stopping at the first one —
    /// this is meant for ingest-time diagnostics, where seeing every problem
    /// in a malformed event at once is more useful than re-running validation
    /// repeatedly to uncover them one at a time.
    ///
    /// Two policy decisions worth knowing about:
    /// - Fields on `event` that aren't declared in this schema are ignored.
    ///   A schema here describes a minimum expected shape, not an exhaustive
    ///   allow-list — SIEM pipelines routinely add enrichment fields (GeoIP,
    ///   threat intel, ...) that a schema won't know about in advance.
    /// - A required field's [`SchemaField::default_value`], if set, satisfies
    ///   its `required` constraint even when the field is physically absent —
    ///   the default is treated as the effective value. `validate` never
    ///   mutates `event`; actually substituting the default in is left to
    ///   the caller.
    ///
    /// This can't be wired into a [`crate::processing::pipeline::Pipeline`]
    /// as a [`crate::processing::pipeline::Processor`] stage: those are bare
    /// `fn` pointers with no room to close over a loaded `Schema`. Call this
    /// directly from application code after parsing, the same way you'd call
    /// your own correlation/detection logic.
    pub fn validate(&self, event: &Event) -> Result<(), Vec<SchemaError>> {
        self.validate_map(event.fields())
    }

    /// Validates a flat field map directly, without requiring an [`Event`]
    /// wrapper — the same recursive object/array/union/constraint logic as
    /// [`Schema::validate`], which delegates here. Used by
    /// [`crate::processing::action::Action`] implementations to validate
    /// action-invocation parameters, which have no arrival time/origin/
    /// raw_data to construct a real `Event` around.
    ///
    /// Generic over the map's key type for the same reason the private
    /// `validate_fields` helper this delegates to already is: this serves
    /// both `Event`'s `String`-keyed top-level fields and any `Text`-keyed
    /// map (e.g. a [`crate::event::field::FieldMap`] — see
    /// [`Schema::validate_field_map`] for a convenience wrapper that
    /// validates one directly).
    pub fn validate_map<K>(&self, fields: &HashMap<K, FieldValue>) -> Result<(), Vec<SchemaError>>
    where
        K: std::borrow::Borrow<str> + std::hash::Hash + Eq,
    {
        self.validate_against(fields)
    }

    /// Validates a [`crate::event::field::FieldMap`] directly — the same
    /// logic as [`Schema::validate_map`]. The typical way an
    /// [`crate::processing::action::Action`] implementation validates its
    /// own invocation params.
    pub fn validate_field_map(&self, fields: &FieldMap) -> Result<(), Vec<SchemaError>> {
        self.validate_against(fields)
    }

    /// Shared core both `validate_map` and `validate_field_map` delegate
    /// to. Generic over [`FieldLookup`] rather than `&HashMap<K,
    /// FieldValue>` directly, since `validate_fields` only ever does point
    /// lookups (`fields.get(name)`/`fields.get(alias)` for the schema's
    /// *own* declared fields) — it never iterates the input map, so no
    /// `Hash`/`Eq`/iteration bound on the caller's map type is actually
    /// needed.
    fn validate_against<F: FieldLookup>(&self, fields: &F) -> Result<(), Vec<SchemaError>> {
        let mut errors = Vec::new();
        self.validate_fields(fields, "", &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validates a field map against this schema's fields, appending any
    /// violations to `errors`. `path` is the dotted field-name prefix built
    /// up so far (empty at the top level), so nested/array errors get a full
    /// path like `user.roles[1]` rather than just `roles`.
    ///
    /// Generic over [`FieldLookup`] so this same logic serves a top-level
    /// [`Event`]'s `HashMap<String, FieldValue>`, a nested
    /// [`FieldValue::Object`]'s `HashMap<Text, FieldValue>` (both via the
    /// blanket `HashMap` impl), and a [`crate::event::field::FieldMap`].
    fn validate_fields<F: FieldLookup>(
        &self,
        fields: &F,
        path: &str,
        errors: &mut Vec<SchemaError>,
    ) {
        for (name, field_def) in &self.fields {
            let full_name = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };

            // A field satisfies its schema entry under its canonical name or
            // any declared alias — an alias exists precisely so a source
            // using an alternate name doesn't trip `required`.
            let value = fields.get(name.as_str()).or_else(|| {
                field_def
                    .aliases
                    .iter()
                    .find_map(|alias| fields.get(alias.as_str()))
            });

            match value {
                Some(v) => self.validate_value(
                    &full_name,
                    v,
                    &field_def.field_type,
                    Some(&field_def.constraints),
                    errors,
                ),
                None if field_def.required && field_def.default_value.is_none() => {
                    errors.push(SchemaError::MissingRequiredField(full_name));
                }
                None => {}
            }
        }
    }

    /// Validates one value against one type (plus, where given, constraints),
    /// recursing into nested objects/arrays/unions. `constraints` is `None`
    /// for array elements, which have a type but no [`FieldConstraints`] of
    /// their own — [`SchemaFieldType::Array`] only carries an element
    /// *type*, not per-element constraints.
    fn validate_value(
        &self,
        field_name: &str,
        value: &FieldValue,
        ty: &SchemaFieldType,
        constraints: Option<&FieldConstraints>,
        errors: &mut Vec<SchemaError>,
    ) {
        match ty {
            SchemaFieldType::Any => return,
            SchemaFieldType::Union(members) => {
                // A value satisfies a union if it validates cleanly against
                // any one member (tried against a throwaway error list, so a
                // non-matching member's errors never leak into `errors`). If
                // none match, report one mismatch against the union as a
                // whole rather than every member's unrelated complaints.
                let matched = members.iter().any(|member| {
                    let mut member_errors = Vec::new();
                    self.validate_value(field_name, value, member, constraints, &mut member_errors);
                    member_errors.is_empty()
                });
                if !matched {
                    errors.push(Self::type_mismatch(field_name, ty, value));
                }
                return;
            }
            _ => {}
        }

        match (value, ty) {
            (FieldValue::Object(map), SchemaFieldType::Object(nested_schema)) => {
                nested_schema.validate_fields(map, field_name, errors);
            }
            (FieldValue::Array(arr), SchemaFieldType::Array(element_ty)) => {
                for (i, element) in arr.iter().enumerate() {
                    let element_name = format!("{field_name}[{i}]");
                    self.validate_value(&element_name, element, element_ty, None, errors);
                }
            }
            _ if !self.is_type_compatible(value, ty) => {
                errors.push(Self::type_mismatch(field_name, ty, value));
                return; // wrong type entirely — constraints wouldn't be meaningful
            }
            _ => {}
        }

        if let Some(c) = constraints
            && let Err(e) = self.validate_constraints(field_name, value, c)
        {
            errors.push(e);
        }
    }

    /// Removes fields from `event` whose value doesn't conform to this
    /// schema — wrong type, or a failed constraint — leaving everything
    /// else untouched.
    ///
    /// Unlike `validate`, `conform` never *adds* anything: a missing
    /// required field stays missing (no default is inserted), and a value
    /// present only under an alias is not renamed to its canonical key —
    /// it's still checked and kept-or-removed under whichever key it was
    /// actually stored under. Fields not declared in this schema are left
    /// alone, the same policy as `validate`. The common case — nothing to
    /// remove — allocates nothing.
    ///
    /// Returns what was removed and why, reusing [`SchemaError`] (though
    /// [`SchemaError::MissingRequiredField`] never appears here — `conform`
    /// only ever inspects fields that are actually present).
    pub fn conform(&self, event: &mut Event) -> Vec<SchemaError> {
        let mut removed = Vec::new();
        self.conform_fields(&mut event.fields, "", &mut removed);
        removed
    }

    /// Prunes non-conforming entries from a field map in place. Generic over
    /// the map's key type for the same reason as `validate_fields`: this
    /// serves both a top-level `Event`'s `HashMap<String, FieldValue>` and a
    /// nested `FieldValue::Object`'s `HashMap<Text, FieldValue>`.
    fn conform_fields<K>(
        &self,
        fields: &mut HashMap<K, FieldValue>,
        path: &str,
        removed: &mut Vec<SchemaError>,
    ) where
        K: std::borrow::Borrow<str> + std::hash::Hash + Eq,
    {
        fields.retain(|key, value| {
            let canonical = self.get_canonical_field_name(key.borrow());
            let Some(field_def) = self.fields.get(&canonical) else {
                return true; // not declared in this schema — leave it alone
            };
            let full_name = if path.is_empty() {
                canonical.clone()
            } else {
                format!("{path}.{canonical}")
            };
            self.conform_value(
                value,
                &field_def.field_type,
                &field_def.constraints,
                &full_name,
                removed,
            )
        });
    }

    /// Checks one value against one type (plus constraints), recursing into
    /// nested objects (pruning their fields in place) and arrays (pruning
    /// non-conforming elements in place) — returns whether `value` should be
    /// kept, pushing the specific reason to `removed` when it shouldn't.
    ///
    /// Container-level constraints (e.g. `min_length` on the object/array
    /// itself) are intentionally not re-checked after pruning — only element
    /// type and per-scalar-field constraints are enforced, to keep this from
    /// growing the same complexity as `validate_value` for a case that's
    /// meant to be a cheap, mechanical cleanup pass.
    fn conform_value(
        &self,
        value: &mut FieldValue,
        ty: &SchemaFieldType,
        constraints: &FieldConstraints,
        full_name: &str,
        removed: &mut Vec<SchemaError>,
    ) -> bool {
        match ty {
            SchemaFieldType::Any => true,
            SchemaFieldType::Union(members) => {
                // Recurse against whichever member matches this value's
                // shape (Object/Array members prune in place; anything else
                // is a plain compatibility check) — there's no meaningful
                // "try a different mutation per candidate member" here.
                let member = match value {
                    FieldValue::Object(_) => members
                        .iter()
                        .find(|m| matches!(m, SchemaFieldType::Object(_))),
                    FieldValue::Array(_) => members
                        .iter()
                        .find(|m| matches!(m, SchemaFieldType::Array(_))),
                    _ => members.iter().find(|m| self.is_type_compatible(value, m)),
                };
                match member {
                    Some(m) => self.conform_value(value, m, constraints, full_name, removed),
                    None => {
                        removed.push(Self::type_mismatch(full_name, ty, value));
                        false
                    }
                }
            }
            SchemaFieldType::Object(nested_schema) => match value {
                FieldValue::Object(map) => {
                    nested_schema.conform_fields(map, full_name, removed);
                    true
                }
                _ => {
                    removed.push(Self::type_mismatch(full_name, ty, value));
                    false
                }
            },
            SchemaFieldType::Array(element_ty) => match value {
                FieldValue::Array(arr) => {
                    let mut index = 0;
                    arr.retain_mut(|element| {
                        let element_name = format!("{full_name}[{index}]");
                        index += 1;
                        self.conform_value(
                            element,
                            element_ty,
                            &FieldConstraints::default(),
                            &element_name,
                            removed,
                        )
                    });
                    true
                }
                _ => {
                    removed.push(Self::type_mismatch(full_name, ty, value));
                    false
                }
            },
            _ => {
                if !self.is_type_compatible(value, ty) {
                    removed.push(Self::type_mismatch(full_name, ty, value));
                    return false;
                }
                match self.validate_constraints(full_name, value, constraints) {
                    Ok(()) => true,
                    Err(e) => {
                        removed.push(e);
                        false
                    }
                }
            }
        }
    }

    fn type_mismatch(
        field_name: &str,
        expected: &SchemaFieldType,
        actual: &FieldValue,
    ) -> SchemaError {
        SchemaError::InvalidFieldType {
            field: field_name.to_string(),
            expected: format!("{:?}", expected),
            actual: format!("{:?}", actual),
        }
    }

    /// Checks whether a scalar value's tag matches a scalar schema type.
    /// `Object`/`Array`/`Union`/`Any` are all resolved by
    /// [`Schema::validate_value`] before this is ever reached, so this only
    /// needs to compare the 8 scalar [`SchemaFieldType`] variants (plus the
    /// numeric widening this crate allows: an `Int`/`Uint` value where a
    /// `Float` field is declared, or a `Uint` value where an `Int` field is
    /// declared).
    fn is_type_compatible(&self, value: &FieldValue, schema_type: &SchemaFieldType) -> bool {
        matches!(
            (value, schema_type),
            (FieldValue::Str(_), SchemaFieldType::Str)
                | (FieldValue::Int(_), SchemaFieldType::Int)
                | (FieldValue::Uint(_), SchemaFieldType::Uint)
                | (FieldValue::Float(_), SchemaFieldType::Float)
                | (FieldValue::Bool(_), SchemaFieldType::Bool)
                | (FieldValue::Bytes(_), SchemaFieldType::Bytes)
                | (FieldValue::Time(_), SchemaFieldType::Time)
                | (FieldValue::Ip(_), SchemaFieldType::Ip)
                | (FieldValue::Int(_), SchemaFieldType::Float)
                | (FieldValue::Uint(_), SchemaFieldType::Float)
                | (FieldValue::Uint(_), SchemaFieldType::Int)
        )
    }

    /// Validate field constraints
    fn validate_constraints(
        &self,
        field_name: &str,
        value: &FieldValue,
        constraints: &FieldConstraints,
    ) -> Result<(), SchemaError> {
        // Min/Max value validation
        if let Some(numeric_value) = self.get_numeric_value(value) {
            if let Some(min) = constraints.min_value
                && numeric_value < min
            {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' value {} is below minimum {}",
                    field_name, numeric_value, min
                )));
            }
            if let Some(max) = constraints.max_value
                && numeric_value > max
            {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' value {} is above maximum {}",
                    field_name, numeric_value, max
                )));
            }
        }

        // Length validation
        let actual_len = self.get_length(value);
        if let Some(min_len) = constraints.min_length
            && actual_len < min_len
        {
            return Err(SchemaError::ValidationFailed(format!(
                "Field '{}' length {} is below minimum {}",
                field_name, actual_len, min_len
            )));
        }
        if let Some(max_len) = constraints.max_length
            && actual_len > max_len
        {
            return Err(SchemaError::ValidationFailed(format!(
                "Field '{}' length {} is above maximum {}",
                field_name, actual_len, max_len
            )));
        }

        // Pattern validation (string fields only — same "doesn't apply to
        // this type" latitude as the numeric/length checks above).
        if let Some(ref pattern) = constraints.pattern {
            let regex = Regex::new(pattern).map_err(|e| {
                SchemaError::ValidationFailed(format!(
                    "Field '{}' has an invalid pattern '{}': {}",
                    field_name, pattern, e
                ))
            })?;
            if let Some(s) = value.as_str()
                && !regex.is_match(s)
            {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' value '{}' does not match pattern '{}'",
                    field_name, s, pattern
                )));
            }
        }

        // Allowed values validation
        if let Some(ref allowed) = constraints.allowed_values
            && !allowed.contains(value)
        {
            return Err(SchemaError::ValidationFailed(format!(
                "Field '{}' has invalid value",
                field_name
            )));
        }

        Ok(())
    }

    fn get_numeric_value(&self, value: &FieldValue) -> Option<f64> {
        match value {
            FieldValue::Int(n) => Some(*n as f64),
            FieldValue::Uint(n) => Some(*n as f64),
            FieldValue::Float(f) => Some(*f),
            FieldValue::Time(t) => Some(t.as_nanos() as f64),
            _ => None,
        }
    }

    fn get_length(&self, value: &FieldValue) -> usize {
        match value {
            FieldValue::Str(s) => s.len(),
            FieldValue::Bytes(b) => b.len(),
            FieldValue::Array(a) => a.len(),
            FieldValue::Object(o) => o.len(),
            _ => 0,
        }
    }

    /// Get canonical field name for an alias
    pub fn get_canonical_field_name(&self, field_name: &str) -> String {
        self.field_mappings
            .get(field_name)
            .cloned()
            .unwrap_or_else(|| field_name.to_string())
    }
}

/// Builder for schema fields
pub struct SchemaFieldBuilder {
    field_type: SchemaFieldType,
    required: bool,
    default_value: Option<FieldValue>,
    description: Option<String>,
    constraints: FieldConstraints,
    aliases: Vec<String>,
    normalize: bool,
}

impl SchemaFieldBuilder {
    pub fn new(field_type: SchemaFieldType) -> Self {
        Self {
            field_type,
            required: false,
            default_value: None,
            description: None,
            constraints: FieldConstraints::default(),
            aliases: Vec::new(),
            normalize: false,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn default_value<V: Into<FieldValue>>(mut self, value: V) -> Self {
        self.default_value = Some(value.into());
        self
    }

    pub fn description<S: Into<String>>(mut self, desc: S) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn alias<S: Into<String>>(mut self, alias: S) -> Self {
        self.aliases.push(alias.into());
        self
    }

    pub fn aliases<I, S>(mut self, aliases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.aliases.extend(aliases.into_iter().map(|s| s.into()));
        self
    }

    pub fn min_value(mut self, min: f64) -> Self {
        self.constraints.min_value = Some(min);
        self
    }

    pub fn max_value(mut self, max: f64) -> Self {
        self.constraints.max_value = Some(max);
        self
    }

    pub fn min_length(mut self, min: usize) -> Self {
        self.constraints.min_length = Some(min);
        self
    }

    pub fn max_length(mut self, max: usize) -> Self {
        self.constraints.max_length = Some(max);
        self
    }

    pub fn pattern<S: Into<String>>(mut self, pattern: S) -> Self {
        self.constraints.pattern = Some(pattern.into());
        self
    }

    pub fn allowed_values<I, V>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<FieldValue>,
    {
        self.constraints.allowed_values = Some(values.into_iter().map(|v| v.into()).collect());
        self
    }

    pub fn normalize(mut self) -> Self {
        self.normalize = true;
        self
    }

    pub fn build(self) -> SchemaField {
        SchemaField {
            field_type: self.field_type,
            required: self.required,
            default_value: self.default_value,
            description: self.description,
            constraints: self.constraints,
            aliases: self.aliases,
            normalize: self.normalize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    ValidationFailed(String),
    MissingRequiredField(String),
    InvalidFieldType {
        field: String,
        expected: String,
        actual: String,
    },
    SchemaNotFound,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::ValidationFailed(msg) => write!(f, "Schema validation failed: {}", msg),
            SchemaError::MissingRequiredField(field) => {
                write!(f, "Missing required field: {}", field)
            }
            SchemaError::InvalidFieldType {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid type for field '{}': expected {}, got {}",
                    field, expected, actual
                )
            }
            SchemaError::SchemaNotFound => write!(f, "Schema not found"),
        }
    }
}

impl std::error::Error for SchemaError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::{Ip, Text, Timestamp};
    use crate::event::{Origin, RawData};
    use std::net::Ipv4Addr;

    fn sample_event() -> Event {
        Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_hostname("test-host"),
            RawData::from_text("raw log line"),
        )
    }

    #[test]
    fn validate_passes_for_a_conforming_event() {
        let mut schema = Schema::new("web_access", "1.0");
        schema.add_field("client_ip", Schema::ip_field().required().build());
        schema.add_field(
            "status_code",
            Schema::int_field()
                .required()
                .min_value(100.0)
                .max_value(599.0)
                .build(),
        );

        let mut event = sample_event();
        event.add_field(
            "client_ip".to_string(),
            FieldValue::Ip(Ip::V4(Ipv4Addr::new(10, 0, 0, 1))),
        );
        event.add_field("status_code".to_string(), FieldValue::Int(200));

        assert_eq!(schema.validate(&event), Ok(()));
    }

    #[test]
    fn validate_map_matches_validate_on_equivalent_fields() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("username", Schema::str_field().required().build());

        let mut event = sample_event();
        event.add_field("username".to_string(), FieldValue::str("alice"));

        let mut map = HashMap::new();
        map.insert("username".to_string(), FieldValue::str("alice"));

        assert_eq!(schema.validate(&event), schema.validate_map(&map));
    }

    #[test]
    fn validate_map_works_against_a_text_keyed_map_too() {
        use crate::event::field::Text;

        let mut schema = Schema::new("s", "1.0");
        schema.add_field("username", Schema::str_field().required().build());

        let mut text_keyed: HashMap<Text, FieldValue> = HashMap::new();
        text_keyed.insert(Text::from("username"), FieldValue::str("alice"));

        assert_eq!(schema.validate_map(&text_keyed), Ok(()));
    }

    #[test]
    fn validate_field_map_matches_validate_map_on_an_equivalent_hash_map() {
        use crate::event::field::{FieldMap, Text};

        let mut schema = Schema::new("s", "1.0");
        schema.add_field("username", Schema::str_field().required().build());

        let mut field_map = FieldMap::new();
        field_map.insert("username", FieldValue::str("alice"));

        let mut equivalent: HashMap<Text, FieldValue> = HashMap::new();
        equivalent.insert(Text::from("username"), FieldValue::str("alice"));

        assert_eq!(
            schema.validate_field_map(&field_map),
            schema.validate_map(&equivalent)
        );
        assert_eq!(schema.validate_field_map(&field_map), Ok(()));
    }

    #[test]
    fn validate_reports_missing_required_field() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("username", Schema::str_field().required().build());

        let event = sample_event();

        assert_eq!(
            schema.validate(&event),
            Err(vec![SchemaError::MissingRequiredField(
                "username".to_string()
            )])
        );
    }

    #[test]
    fn validate_missing_required_field_with_default_is_not_an_error() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "severity",
            Schema::int_field()
                .required()
                .default_value(FieldValue::Int(0))
                .build(),
        );

        let event = sample_event();

        assert_eq!(schema.validate(&event), Ok(()));
    }

    #[test]
    fn validate_missing_required_field_satisfied_by_alias() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "username",
            Schema::str_field().required().alias("user").build(),
        );

        let mut event = sample_event();
        event.add_field("user".to_string(), FieldValue::str("alice"));

        assert_eq!(schema.validate(&event), Ok(()));
    }

    #[test]
    fn validate_reports_wrong_type() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("status_code", Schema::int_field().required().build());

        let mut event = sample_event();
        event.add_field("status_code".to_string(), FieldValue::str("not-a-number"));

        assert_eq!(
            schema.validate(&event),
            Err(vec![SchemaError::InvalidFieldType {
                field: "status_code".to_string(),
                expected: format!("{:?}", SchemaFieldType::Int),
                actual: format!("{:?}", FieldValue::str("not-a-number")),
            }])
        );
    }

    #[test]
    fn validate_ignores_fields_not_declared_in_schema() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("username", Schema::str_field().required().build());

        let mut event = sample_event();
        event.add_field("username".to_string(), FieldValue::str("alice"));
        event.add_field(
            "enrichment.geoip.country".to_string(),
            FieldValue::str("US"),
        );

        assert_eq!(schema.validate(&event), Ok(()));
    }

    #[test]
    fn validate_collects_every_violation_not_just_the_first() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("username", Schema::str_field().required().build());
        schema.add_field("status_code", Schema::int_field().required().build());

        let event = sample_event();

        let errors = schema.validate(&event).unwrap_err();
        assert_eq!(errors.len(), 2);
        assert!(errors.contains(&SchemaError::MissingRequiredField("username".to_string())));
        assert!(errors.contains(&SchemaError::MissingRequiredField(
            "status_code".to_string()
        )));
    }

    #[test]
    fn validate_recurses_into_nested_object() {
        let mut user_schema = Schema::new("user", "1.0");
        user_schema.add_field("id", Schema::int_field().required().build());

        let mut schema = Schema::new("s", "1.0");
        schema.add_field("user", Schema::object_field(user_schema).required().build());

        let mut bad_user = HashMap::new();
        bad_user.insert(Text::from("id"), FieldValue::str("not-an-int"));
        let mut event = sample_event();
        event.add_field("user".to_string(), FieldValue::Object(bad_user));

        assert_eq!(
            schema.validate(&event),
            Err(vec![SchemaError::InvalidFieldType {
                field: "user.id".to_string(),
                expected: format!("{:?}", SchemaFieldType::Int),
                actual: format!("{:?}", FieldValue::str("not-an-int")),
            }])
        );
    }

    #[test]
    fn validate_recurses_into_array_elements() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "tags",
            Schema::array_field(SchemaFieldType::Str).required().build(),
        );

        let mut event = sample_event();
        event.add_field(
            "tags".to_string(),
            FieldValue::Array(vec![FieldValue::str("ok"), FieldValue::Int(5)]),
        );

        assert_eq!(
            schema.validate(&event),
            Err(vec![SchemaError::InvalidFieldType {
                field: "tags[1]".to_string(),
                expected: format!("{:?}", SchemaFieldType::Str),
                actual: format!("{:?}", FieldValue::Int(5)),
            }])
        );
    }

    #[test]
    fn validate_union_accepts_any_matching_member() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "port",
            SchemaFieldBuilder::new(SchemaFieldType::Union(vec![
                SchemaFieldType::Str,
                SchemaFieldType::Int,
            ]))
            .required()
            .build(),
        );

        let mut string_port_event = sample_event();
        string_port_event.add_field("port".to_string(), FieldValue::str("443"));
        assert_eq!(schema.validate(&string_port_event), Ok(()));

        let mut int_port_event = sample_event();
        int_port_event.add_field("port".to_string(), FieldValue::Int(443));
        assert_eq!(schema.validate(&int_port_event), Ok(()));

        let mut bad_event = sample_event();
        bad_event.add_field("port".to_string(), FieldValue::Bool(true));
        assert!(schema.validate(&bad_event).is_err());
    }

    #[test]
    fn validate_enforces_pattern_constraint() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "request_id",
            Schema::str_field()
                .required()
                .pattern(r"^[0-9a-f]{8}$")
                .build(),
        );

        let mut good = sample_event();
        good.add_field("request_id".to_string(), FieldValue::str("deadbeef"));
        assert_eq!(schema.validate(&good), Ok(()));

        let mut bad = sample_event();
        bad.add_field("request_id".to_string(), FieldValue::str("not-hex!"));
        assert!(schema.validate(&bad).is_err());
    }

    #[test]
    fn validate_reports_invalid_regex_pattern_as_a_validation_error() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "request_id",
            Schema::str_field().required().pattern("[").build(),
        );

        let mut event = sample_event();
        event.add_field("request_id".to_string(), FieldValue::str("anything"));

        assert!(schema.validate(&event).is_err());
    }

    #[test]
    fn validate_enforces_min_max_and_length_constraints() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "status_code",
            Schema::int_field()
                .required()
                .min_value(100.0)
                .max_value(599.0)
                .build(),
        );
        schema.add_field(
            "username",
            Schema::str_field()
                .required()
                .min_length(3)
                .max_length(20)
                .build(),
        );

        let mut event = sample_event();
        event.add_field("status_code".to_string(), FieldValue::Int(700));
        event.add_field("username".to_string(), FieldValue::str("ab"));

        let errors = schema.validate(&event).unwrap_err();
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn conform_removes_a_field_with_the_wrong_type() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("status_code", Schema::int_field().required().build());

        let mut event = sample_event();
        event.add_field("status_code".to_string(), FieldValue::str("not-a-number"));

        let removed = schema.conform(&mut event);

        assert!(event.get_field("status_code").is_none());
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn conform_leaves_a_conforming_field_untouched() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field("status_code", Schema::int_field().required().build());

        let mut event = sample_event();
        event.add_field("status_code".to_string(), FieldValue::Int(200));

        let removed = schema.conform(&mut event);

        assert_eq!(event.get_field("status_code"), Some(&FieldValue::Int(200)));
        assert!(removed.is_empty());
    }

    #[test]
    fn conform_does_not_insert_a_missing_required_field_even_with_a_default() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "severity",
            Schema::int_field()
                .required()
                .default_value(FieldValue::Int(0))
                .build(),
        );

        let mut event = sample_event();
        let removed = schema.conform(&mut event);

        assert!(event.get_field("severity").is_none());
        assert!(removed.is_empty());
    }

    #[test]
    fn conform_leaves_fields_not_declared_in_the_schema_untouched() {
        let schema = Schema::new("s", "1.0");
        let mut event = sample_event();
        event.add_field(
            "enrichment.geoip.country".to_string(),
            FieldValue::str("US"),
        );

        let removed = schema.conform(&mut event);

        assert_eq!(
            event.get_field("enrichment.geoip.country"),
            Some(&FieldValue::str("US"))
        );
        assert!(removed.is_empty());
    }

    #[test]
    fn conform_recurses_into_nested_object_pruning_only_the_bad_subfield() {
        let mut user_schema = Schema::new("user", "1.0");
        user_schema.add_field("id", Schema::int_field().required().build());
        user_schema.add_field("name", Schema::str_field().required().build());

        let mut schema = Schema::new("s", "1.0");
        schema.add_field("user", Schema::object_field(user_schema).required().build());

        let mut user_map = HashMap::new();
        user_map.insert(Text::from("id"), FieldValue::str("not-an-int"));
        user_map.insert(Text::from("name"), FieldValue::str("alice"));
        let mut event = sample_event();
        event.add_field("user".to_string(), FieldValue::Object(user_map));

        let removed = schema.conform(&mut event);

        match event.get_field("user") {
            Some(FieldValue::Object(map)) => {
                assert!(map.get("id").is_none());
                assert_eq!(map.get("name"), Some(&FieldValue::str("alice")));
            }
            other => panic!("expected user to remain a (pruned) Object, got {other:?}"),
        }
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn conform_prunes_non_conforming_array_elements_keeping_the_rest() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "tags",
            Schema::array_field(SchemaFieldType::Str).required().build(),
        );

        let mut event = sample_event();
        event.add_field(
            "tags".to_string(),
            FieldValue::Array(vec![
                FieldValue::str("ok"),
                FieldValue::Int(5),
                FieldValue::str("also-ok"),
            ]),
        );

        let removed = schema.conform(&mut event);

        match event.get_field("tags") {
            Some(FieldValue::Array(arr)) => {
                assert_eq!(
                    arr,
                    &vec![FieldValue::str("ok"), FieldValue::str("also-ok")]
                );
            }
            other => panic!("expected tags to remain a (pruned) Array, got {other:?}"),
        }
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn conform_removes_a_field_that_violates_a_constraint() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "status_code",
            Schema::int_field()
                .required()
                .min_value(100.0)
                .max_value(599.0)
                .build(),
        );

        let mut event = sample_event();
        event.add_field("status_code".to_string(), FieldValue::Int(999));

        let removed = schema.conform(&mut event);

        assert!(event.get_field("status_code").is_none());
        assert_eq!(
            removed,
            vec![SchemaError::ValidationFailed(
                "Field 'status_code' value 999 is above maximum 599".to_string()
            )]
        );
    }

    #[test]
    fn conform_keeps_a_value_present_under_an_alias_without_renaming_it() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "username",
            Schema::str_field().required().alias("user").build(),
        );

        let mut event = sample_event();
        event.add_field("user".to_string(), FieldValue::str("alice"));

        let removed = schema.conform(&mut event);

        assert_eq!(event.get_field("user"), Some(&FieldValue::str("alice")));
        assert!(event.get_field("username").is_none());
        assert!(removed.is_empty());
    }

    #[test]
    fn conform_removes_a_bad_value_present_under_an_alias() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "username",
            Schema::str_field().required().alias("user").build(),
        );

        let mut event = sample_event();
        event.add_field("user".to_string(), FieldValue::Int(5));

        let removed = schema.conform(&mut event);

        assert!(event.get_field("user").is_none());
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn conform_keeps_a_union_value_matching_any_member() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "port",
            SchemaFieldBuilder::new(SchemaFieldType::Union(vec![
                SchemaFieldType::Str,
                SchemaFieldType::Int,
            ]))
            .required()
            .build(),
        );

        let mut event = sample_event();
        event.add_field("port".to_string(), FieldValue::Int(443));

        let removed = schema.conform(&mut event);

        assert_eq!(event.get_field("port"), Some(&FieldValue::Int(443)));
        assert!(removed.is_empty());
    }

    #[test]
    fn conform_removes_a_union_value_matching_no_member() {
        let mut schema = Schema::new("s", "1.0");
        schema.add_field(
            "port",
            SchemaFieldBuilder::new(SchemaFieldType::Union(vec![
                SchemaFieldType::Str,
                SchemaFieldType::Int,
            ]))
            .required()
            .build(),
        );

        let mut event = sample_event();
        event.add_field("port".to_string(), FieldValue::Bool(true));

        let removed = schema.conform(&mut event);

        assert!(event.get_field("port").is_none());
        assert_eq!(removed.len(), 1);
    }
}
