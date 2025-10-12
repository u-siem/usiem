/// Error type for field value conversion failures
#[derive(Debug, Clone, PartialEq)]
pub enum FieldConversionError {
    /// The field value type cannot be converted to the target type
    IncompatibleType {
        from: &'static str,
        to: &'static str,
    },
    /// String parsing failed
    ParseError {
        value: String,
        target_type: &'static str,
        error: String,
    },
    /// Numeric value is out of range for target type
    OutOfRange {
        value: String,
        target_type: &'static str,
    },
    /// IP address parsing failed
    InvalidIpAddress(String),
    /// Time parsing failed
    InvalidTimeFormat(String),
    /// Unsupported operation for field type
    UnsupportedOperation {
        operation: &'static str,
        field_type: String,
    },
    /// Division by zero
    DivisionByZero,
}

impl std::fmt::Display for FieldConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldConversionError::IncompatibleType { from, to } => {
                write!(f, "Cannot convert from {} to {}", from, to)
            }
            FieldConversionError::ParseError {
                value,
                target_type,
                error,
            } => {
                write!(
                    f,
                    "Failed to parse '{}' as {}: {}",
                    value, target_type, error
                )
            }
            FieldConversionError::OutOfRange { value, target_type } => {
                write!(
                    f,
                    "Value '{}' is out of range for type {}",
                    value, target_type
                )
            }
            FieldConversionError::InvalidIpAddress(addr) => {
                write!(f, "Invalid IP address: {}", addr)
            }
            FieldConversionError::InvalidTimeFormat(time_str) => {
                write!(f, "Invalid time format: {}", time_str)
            }
            FieldConversionError::UnsupportedOperation {
                operation,
                field_type,
            } => {
                write!(
                    f,
                    "Unsupported operation '{}' for field type {}",
                    operation, field_type
                )
            }
            FieldConversionError::DivisionByZero => {
                write!(f, "Division by zero")
            }
        }
    }
}

impl std::error::Error for FieldConversionError {}
