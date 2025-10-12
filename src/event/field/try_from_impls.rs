use super::error::FieldConversionError;
use super::field_value::FieldValue;
use super::ip::Ip;
use super::time::Timestamp;

// TryFrom implementations for owned values
impl TryFrom<FieldValue> for String {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Str(s) => Ok(s.to_string()),
            FieldValue::Int(n) => Ok(n.to_string()),
            FieldValue::Uint(n) => Ok(n.to_string()),
            FieldValue::Float(f) => Ok(f.to_string()),
            FieldValue::Bool(b) => Ok(b.to_string()),
            FieldValue::Time(t) => Ok(t.to_rfc3339()),
            FieldValue::Ip(ip) => Ok(ip.to_string()),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "String",
            }),
        }
    }
}

// TryFrom implementations for borrowed values
impl TryFrom<&FieldValue> for String {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Str(s) => Ok(s.to_string()),
            FieldValue::Int(n) => Ok(n.to_string()),
            FieldValue::Uint(n) => Ok(n.to_string()),
            FieldValue::Float(f) => Ok(f.to_string()),
            FieldValue::Bool(b) => Ok(b.to_string()),
            FieldValue::Time(t) => Ok(t.to_rfc3339()),
            FieldValue::Ip(ip) => Ok(ip.to_string()),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "String",
            }),
        }
    }
}

impl TryFrom<FieldValue> for i64 {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Int(n) => Ok(n),
            FieldValue::Uint(n) => n.try_into().map_err(|_| FieldConversionError::OutOfRange {
                value: n.to_string(),
                target_type: "i64",
            }),
            FieldValue::Float(f) => {
                if f.is_finite() && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                    Ok(f as i64)
                } else {
                    Err(FieldConversionError::OutOfRange {
                        value: f.to_string(),
                        target_type: "i64",
                    })
                }
            }
            FieldValue::Str(s) => s
                .parse::<i64>()
                .map_err(|e| FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "i64",
                    error: e.to_string(),
                }),
            FieldValue::Bool(b) => Ok(if b { 1 } else { 0 }),
            FieldValue::Time(t) => Ok(t.as_nanos()),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "i64",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for i64 {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Int(n) => Ok(*n),
            FieldValue::Uint(n) => (*n)
                .try_into()
                .map_err(|_| FieldConversionError::OutOfRange {
                    value: n.to_string(),
                    target_type: "i64",
                }),
            FieldValue::Float(f) => {
                if f.is_finite() && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 {
                    Ok(*f as i64)
                } else {
                    Err(FieldConversionError::OutOfRange {
                        value: f.to_string(),
                        target_type: "i64",
                    })
                }
            }
            FieldValue::Str(s) => s
                .parse::<i64>()
                .map_err(|e| FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "i64",
                    error: e.to_string(),
                }),
            FieldValue::Bool(b) => Ok(if *b { 1 } else { 0 }),
            FieldValue::Time(t) => Ok(t.as_nanos()),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "i64",
            }),
        }
    }
}

impl TryFrom<FieldValue> for u64 {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Uint(n) => Ok(n),
            FieldValue::Int(n) => n.try_into().map_err(|_| FieldConversionError::OutOfRange {
                value: n.to_string(),
                target_type: "u64",
            }),
            FieldValue::Float(f) => {
                if f.is_finite() && f >= 0.0 && f <= u64::MAX as f64 {
                    Ok(f as u64)
                } else {
                    Err(FieldConversionError::OutOfRange {
                        value: f.to_string(),
                        target_type: "u64",
                    })
                }
            }
            FieldValue::Str(s) => s
                .parse::<u64>()
                .map_err(|e| FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "u64",
                    error: e.to_string(),
                }),
            FieldValue::Bool(b) => Ok(if b { 1 } else { 0 }),
            FieldValue::Time(t) => Ok(t.as_nanos() as u64),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "u64",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for u64 {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Uint(n) => Ok(*n),
            FieldValue::Int(n) => (*n)
                .try_into()
                .map_err(|_| FieldConversionError::OutOfRange {
                    value: n.to_string(),
                    target_type: "u64",
                }),
            FieldValue::Float(f) => {
                if f.is_finite() && *f >= 0.0 && *f <= u64::MAX as f64 {
                    Ok(*f as u64)
                } else {
                    Err(FieldConversionError::OutOfRange {
                        value: f.to_string(),
                        target_type: "u64",
                    })
                }
            }
            FieldValue::Str(s) => s
                .parse::<u64>()
                .map_err(|e| FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "u64",
                    error: e.to_string(),
                }),
            FieldValue::Bool(b) => Ok(if *b { 1 } else { 0 }),
            FieldValue::Time(t) => Ok(t.as_nanos() as u64),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "u64",
            }),
        }
    }
}

impl TryFrom<FieldValue> for i32 {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        let i64_val: i64 = value.try_into()?;
        i64_val
            .try_into()
            .map_err(|_| FieldConversionError::OutOfRange {
                value: i64_val.to_string(),
                target_type: "i32",
            })
    }
}

impl TryFrom<&FieldValue> for i32 {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        let i64_val: i64 = value.try_into()?;
        i64_val
            .try_into()
            .map_err(|_| FieldConversionError::OutOfRange {
                value: i64_val.to_string(),
                target_type: "i32",
            })
    }
}

impl TryFrom<FieldValue> for u32 {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        let u64_val: u64 = value.try_into()?;
        u64_val
            .try_into()
            .map_err(|_| FieldConversionError::OutOfRange {
                value: u64_val.to_string(),
                target_type: "u32",
            })
    }
}

impl TryFrom<&FieldValue> for u32 {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        let u64_val: u64 = value.try_into()?;
        u64_val
            .try_into()
            .map_err(|_| FieldConversionError::OutOfRange {
                value: u64_val.to_string(),
                target_type: "u32",
            })
    }
}

impl TryFrom<FieldValue> for f64 {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Float(f) => Ok(f),
            FieldValue::Int(n) => Ok(n as f64),
            FieldValue::Uint(n) => Ok(n as f64),
            FieldValue::Str(s) => s
                .parse::<f64>()
                .map_err(|e| FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "f64",
                    error: e.to_string(),
                }),
            FieldValue::Bool(b) => Ok(if b { 1.0 } else { 0.0 }),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "f64",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for f64 {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Float(f) => Ok(*f),
            FieldValue::Int(n) => Ok(*n as f64),
            FieldValue::Uint(n) => Ok(*n as f64),
            FieldValue::Str(s) => s
                .parse::<f64>()
                .map_err(|e| FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "f64",
                    error: e.to_string(),
                }),
            FieldValue::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "f64",
            }),
        }
    }
}

impl TryFrom<FieldValue> for f32 {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        let f64_val: f64 = value.try_into()?;
        if f64_val.is_finite() && f64_val >= f32::MIN as f64 && f64_val <= f32::MAX as f64 {
            Ok(f64_val as f32)
        } else {
            Err(FieldConversionError::OutOfRange {
                value: f64_val.to_string(),
                target_type: "f32",
            })
        }
    }
}

impl TryFrom<&FieldValue> for f32 {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        let f64_val: f64 = value.try_into()?;
        if f64_val.is_finite() && f64_val >= f32::MIN as f64 && f64_val <= f32::MAX as f64 {
            Ok(f64_val as f32)
        } else {
            Err(FieldConversionError::OutOfRange {
                value: f64_val.to_string(),
                target_type: "f32",
            })
        }
    }
}

impl TryFrom<FieldValue> for bool {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Bool(b) => Ok(b),
            FieldValue::Int(n) => Ok(n != 0),
            FieldValue::Uint(n) => Ok(n != 0),
            FieldValue::Float(f) => Ok(f != 0.0),
            FieldValue::Str(s) => match s.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "t" | "y" => Ok(true),
                "false" | "0" | "no" | "off" | "f" | "n" => Ok(false),
                _ => Err(FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "bool",
                    error: "Invalid boolean string".to_string(),
                }),
            },
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "bool",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for bool {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Bool(b) => Ok(*b),
            FieldValue::Int(n) => Ok(*n != 0),
            FieldValue::Uint(n) => Ok(*n != 0),
            FieldValue::Float(f) => Ok(*f != 0.0),
            FieldValue::Str(s) => match s.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "t" | "y" => Ok(true),
                "false" | "0" | "no" | "off" | "f" | "n" => Ok(false),
                _ => Err(FieldConversionError::ParseError {
                    value: s.to_string(),
                    target_type: "bool",
                    error: "Invalid boolean string".to_string(),
                }),
            },
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "bool",
            }),
        }
    }
}

impl TryFrom<FieldValue> for Timestamp {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Time(t) => Ok(t),
            FieldValue::Int(n) => Ok(Timestamp::from_nanos(n)),
            FieldValue::Uint(n) => Ok(Timestamp::from_nanos(n as i64)),
            FieldValue::Str(s) => Timestamp::from_rfc3339(&s)
                .map_err(|e| FieldConversionError::InvalidTimeFormat(format!("{}: {}", s, e))),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "Timestamp",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for Timestamp {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Time(t) => Ok(*t),
            FieldValue::Int(n) => Ok(Timestamp::from_nanos(*n)),
            FieldValue::Uint(n) => Ok(Timestamp::from_nanos(*n as i64)),
            FieldValue::Str(s) => Timestamp::from_rfc3339(s)
                .map_err(|e| FieldConversionError::InvalidTimeFormat(format!("{}: {}", s, e))),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "Timestamp",
            }),
        }
    }
}

impl TryFrom<FieldValue> for Ip {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Ip(ip) => Ok(ip),
            FieldValue::Str(s) => {
                Ip::from_str(&s).map_err(|_| FieldConversionError::InvalidIpAddress(s.to_string()))
            }
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "Ip",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for Ip {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Ip(ip) => Ok(*ip),
            FieldValue::Str(s) => {
                Ip::from_str(s).map_err(|_| FieldConversionError::InvalidIpAddress(s.to_string()))
            }
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "Ip",
            }),
        }
    }
}

impl TryFrom<FieldValue> for Vec<u8> {
    type Error = FieldConversionError;

    fn try_from(value: FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Bytes(bytes) => Ok(bytes),
            FieldValue::Str(s) => Ok(s.as_bytes().to_vec()),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "Vec<u8>",
            }),
        }
    }
}

impl TryFrom<&FieldValue> for Vec<u8> {
    type Error = FieldConversionError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Bytes(bytes) => Ok(bytes.clone()),
            FieldValue::Str(s) => Ok(s.as_bytes().to_vec()),
            _ => Err(FieldConversionError::IncompatibleType {
                from: value.type_name(),
                to: "Vec<u8>",
            }),
        }
    }
}
