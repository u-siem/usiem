use super::field::FieldValue;
use std::borrow::Cow;
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

    /// Custom validation function name
    pub custom_validator: Option<String>,
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

    /// Creation timestamp
    pub created: Option<u64>,

    /// Last modified timestamp
    pub modified: Option<u64>,
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

    /// Validate a specific field value against its definition
    fn validate_field_value(
        &self,
        field_name: &str,
        value: &FieldValue,
        field_def: &SchemaField,
    ) -> Result<(), SchemaError> {
        // Type validation
        if !self.is_type_compatible(value, &field_def.field_type) {
            return Err(SchemaError::InvalidFieldType {
                field: field_name.to_string(),
                expected: format!("{:?}", field_def.field_type),
                actual: format!("{:?}", value),
            });
        }

        // Constraint validation
        self.validate_constraints(field_name, value, &field_def.constraints)?;

        Ok(())
    }

    /// Check if a field value is compatible with a schema type
    fn is_type_compatible(&self, value: &FieldValue, schema_type: &SchemaFieldType) -> bool {
        match (value, schema_type) {
            (FieldValue::Str(_), SchemaFieldType::Str) => true,
            (FieldValue::Int(_), SchemaFieldType::Int) => true,
            (FieldValue::Uint(_), SchemaFieldType::Uint) => true,
            (FieldValue::Float(_), SchemaFieldType::Float) => true,
            (FieldValue::Bool(_), SchemaFieldType::Bool) => true,
            (FieldValue::Bytes(_), SchemaFieldType::Bytes) => true,
            (FieldValue::Time(_), SchemaFieldType::Time) => true,
            (FieldValue::Ip(_), SchemaFieldType::Ip) => true,
            (FieldValue::Object(_), SchemaFieldType::Object(_)) => true, // TODO: Validate nested schema
            (FieldValue::Array(_), SchemaFieldType::Array(_)) => true, // TODO: Validate element types
            (_, SchemaFieldType::Union(types)) => {
                types.iter().any(|t| self.is_type_compatible(value, t))
            }
            (_, SchemaFieldType::Any) => true,

            // Allow numeric conversions
            (FieldValue::Int(_), SchemaFieldType::Float) => true,
            (FieldValue::Uint(_), SchemaFieldType::Float) => true,
            (FieldValue::Uint(_), SchemaFieldType::Int) => true, // Check bounds later

            _ => false,
        }
    }

    /// Validate field constraints
    fn validate_constraints(
        &self,
        field_name: &str,
        value: &FieldValue,
        constraints: &FieldConstraints,
    ) -> Result<(), SchemaError> {
        // Min/Max value validation
        if let (Some(min), Some(numeric_value)) =
            (constraints.min_value, self.get_numeric_value(value))
        {
            if numeric_value < min {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' value {} is below minimum {}",
                    field_name, numeric_value, min
                )));
            }
        }

        if let (Some(max), Some(numeric_value)) =
            (constraints.max_value, self.get_numeric_value(value))
        {
            if numeric_value > max {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' value {} is above maximum {}",
                    field_name, numeric_value, max
                )));
            }
        }

        // Length validation
        if let Some(min_len) = constraints.min_length {
            let actual_len = self.get_length(value);
            if actual_len < min_len {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' length {} is below minimum {}",
                    field_name, actual_len, min_len
                )));
            }
        }

        if let Some(max_len) = constraints.max_length {
            let actual_len = self.get_length(value);
            if actual_len > max_len {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' length {} is above maximum {}",
                    field_name, actual_len, max_len
                )));
            }
        }

        // Allowed values validation
        if let Some(ref allowed) = constraints.allowed_values {
            if !allowed.contains(value) {
                return Err(SchemaError::ValidationFailed(format!(
                    "Field '{}' has invalid value",
                    field_name
                )));
            }
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

#[derive(Debug, Clone)]
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
