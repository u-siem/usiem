use std::cmp::{Ordering, PartialOrd};
use std::fmt;
use std::net::IpAddr;
use std::ops::{Add, Div, Mul, Rem, Sub};

use super::error::FieldConversionError;
use super::field_value::FieldValue;

// Mathematical operations for FieldValue
impl Add for FieldValue {
    type Output = Result<FieldValue, FieldConversionError>;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (FieldValue::Int(a), FieldValue::Int(b)) => Ok(FieldValue::Int(a + b)),
            (FieldValue::Uint(a), FieldValue::Uint(b)) => Ok(FieldValue::Uint(a + b)),
            (FieldValue::Float(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a + b)),

            // Mixed numeric conversions
            (FieldValue::Int(a), FieldValue::Uint(b)) => {
                if a >= 0 {
                    Ok(FieldValue::Uint((a as u64) + b))
                } else {
                    Ok(FieldValue::Int(a + (b as i64)))
                }
            }
            (FieldValue::Uint(a), FieldValue::Int(b)) => {
                if b >= 0 {
                    Ok(FieldValue::Uint(a + (b as u64)))
                } else {
                    Ok(FieldValue::Int((a as i64) + b))
                }
            }
            (FieldValue::Int(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a as f64 + b)),
            (FieldValue::Float(a), FieldValue::Int(b)) => Ok(FieldValue::Float(a + b as f64)),
            (FieldValue::Uint(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a as f64 + b)),
            (FieldValue::Float(a), FieldValue::Uint(b)) => Ok(FieldValue::Float(a + b as f64)),

            // String concatenation
            (FieldValue::Str(a), FieldValue::Str(b)) => {
                let mut result = a.to_string();
                result.push_str(&b);
                Ok(FieldValue::string(result))
            }

            // Time arithmetic
            (FieldValue::Time(t), FieldValue::Int(secs)) => Ok(FieldValue::Time(t.add_secs(secs))),
            (FieldValue::Int(secs), FieldValue::Time(t)) => Ok(FieldValue::Time(t.add_secs(secs))),

            (a, b) => Err(FieldConversionError::UnsupportedOperation {
                operation: "addition",
                field_type: format!("{} + {}", a.type_name(), b.type_name()),
            }),
        }
    }
}

impl Sub for FieldValue {
    type Output = Result<FieldValue, FieldConversionError>;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (FieldValue::Int(a), FieldValue::Int(b)) => Ok(FieldValue::Int(a - b)),
            (FieldValue::Uint(a), FieldValue::Uint(b)) => {
                if a >= b {
                    Ok(FieldValue::Uint(a - b))
                } else {
                    Ok(FieldValue::Int((a as i64) - (b as i64)))
                }
            }
            (FieldValue::Float(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a - b)),

            // Mixed numeric conversions
            (FieldValue::Int(a), FieldValue::Uint(b)) => Ok(FieldValue::Int(a - (b as i64))),
            (FieldValue::Uint(a), FieldValue::Int(b)) => {
                if b >= 0 && a >= (b as u64) {
                    Ok(FieldValue::Uint(a - (b as u64)))
                } else {
                    Ok(FieldValue::Int((a as i64) - b))
                }
            }
            (FieldValue::Int(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a as f64 - b)),
            (FieldValue::Float(a), FieldValue::Int(b)) => Ok(FieldValue::Float(a - b as f64)),
            (FieldValue::Uint(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a as f64 - b)),
            (FieldValue::Float(a), FieldValue::Uint(b)) => Ok(FieldValue::Float(a - b as f64)),

            // Time arithmetic
            (FieldValue::Time(a), FieldValue::Time(b)) => {
                Ok(FieldValue::Int(a.as_nanos() - b.as_nanos()))
            }
            (FieldValue::Time(t), FieldValue::Int(secs)) => Ok(FieldValue::Time(t.sub_secs(secs))),

            (a, b) => Err(FieldConversionError::UnsupportedOperation {
                operation: "subtraction",
                field_type: format!("{} - {}", a.type_name(), b.type_name()),
            }),
        }
    }
}

impl Mul for FieldValue {
    type Output = Result<FieldValue, FieldConversionError>;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (FieldValue::Int(a), FieldValue::Int(b)) => Ok(FieldValue::Int(a * b)),
            (FieldValue::Uint(a), FieldValue::Uint(b)) => Ok(FieldValue::Uint(a * b)),
            (FieldValue::Float(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a * b)),

            // Mixed numeric conversions
            (FieldValue::Int(a), FieldValue::Uint(b)) => {
                if a >= 0 {
                    Ok(FieldValue::Uint((a as u64) * b))
                } else {
                    Ok(FieldValue::Int(a * (b as i64)))
                }
            }
            (FieldValue::Uint(a), FieldValue::Int(b)) => {
                if b >= 0 {
                    Ok(FieldValue::Uint(a * (b as u64)))
                } else {
                    Ok(FieldValue::Int((a as i64) * b))
                }
            }
            (FieldValue::Int(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a as f64 * b)),
            (FieldValue::Float(a), FieldValue::Int(b)) => Ok(FieldValue::Float(a * b as f64)),
            (FieldValue::Uint(a), FieldValue::Float(b)) => Ok(FieldValue::Float(a as f64 * b)),
            (FieldValue::Float(a), FieldValue::Uint(b)) => Ok(FieldValue::Float(a * b as f64)),

            (a, b) => Err(FieldConversionError::UnsupportedOperation {
                operation: "multiplication",
                field_type: format!("{} * {}", a.type_name(), b.type_name()),
            }),
        }
    }
}

impl Div for FieldValue {
    type Output = Result<FieldValue, FieldConversionError>;

    fn div(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (FieldValue::Int(a), FieldValue::Int(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Int(a / b))
                }
            }
            (FieldValue::Uint(a), FieldValue::Uint(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Uint(a / b))
                }
            }
            (FieldValue::Float(a), FieldValue::Float(b)) => {
                if b == 0.0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a / b))
                }
            }

            // Mixed numeric conversions - always return float for division
            (FieldValue::Int(a), FieldValue::Uint(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a as f64 / b as f64))
                }
            }
            (FieldValue::Uint(a), FieldValue::Int(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a as f64 / b as f64))
                }
            }
            (FieldValue::Int(a), FieldValue::Float(b)) => {
                if b == 0.0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a as f64 / b))
                }
            }
            (FieldValue::Float(a), FieldValue::Int(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a / b as f64))
                }
            }
            (FieldValue::Uint(a), FieldValue::Float(b)) => {
                if b == 0.0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a as f64 / b))
                }
            }
            (FieldValue::Float(a), FieldValue::Uint(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a / b as f64))
                }
            }

            (a, b) => Err(FieldConversionError::UnsupportedOperation {
                operation: "division",
                field_type: format!("{} / {}", a.type_name(), b.type_name()),
            }),
        }
    }
}

impl Rem for FieldValue {
    type Output = Result<FieldValue, FieldConversionError>;

    fn rem(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (FieldValue::Int(a), FieldValue::Int(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Int(a % b))
                }
            }
            (FieldValue::Uint(a), FieldValue::Uint(b)) => {
                if b == 0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Uint(a % b))
                }
            }
            (FieldValue::Float(a), FieldValue::Float(b)) => {
                if b == 0.0 {
                    Err(FieldConversionError::DivisionByZero)
                } else {
                    Ok(FieldValue::Float(a % b))
                }
            }

            (a, b) => Err(FieldConversionError::UnsupportedOperation {
                operation: "modulo",
                field_type: format!("{} % {}", a.type_name(), b.type_name()),
            }),
        }
    }
}

// Ordering for comparable field values
impl PartialOrd for FieldValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            // Numeric comparisons
            (FieldValue::Int(a), FieldValue::Int(b)) => a.partial_cmp(b),
            (FieldValue::Uint(a), FieldValue::Uint(b)) => a.partial_cmp(b),
            (FieldValue::Float(a), FieldValue::Float(b)) => a.partial_cmp(b),

            // Mixed numeric comparisons
            (FieldValue::Int(a), FieldValue::Uint(b)) => {
                if *a < 0 {
                    Some(Ordering::Less)
                } else {
                    (*a as u64).partial_cmp(b)
                }
            }
            (FieldValue::Uint(a), FieldValue::Int(b)) => {
                if *b < 0 {
                    Some(Ordering::Greater)
                } else {
                    a.partial_cmp(&(*b as u64))
                }
            }
            (FieldValue::Int(a), FieldValue::Float(b)) => (*a as f64).partial_cmp(b),
            (FieldValue::Float(a), FieldValue::Int(b)) => a.partial_cmp(&(*b as f64)),
            (FieldValue::Uint(a), FieldValue::Float(b)) => (*a as f64).partial_cmp(b),
            (FieldValue::Float(a), FieldValue::Uint(b)) => a.partial_cmp(&(*b as f64)),

            // String comparisons
            (FieldValue::Str(a), FieldValue::Str(b)) => a.as_ref().partial_cmp(b.as_ref()),

            // Boolean comparisons
            (FieldValue::Bool(a), FieldValue::Bool(b)) => a.partial_cmp(b),

            // Time comparisons
            (FieldValue::Time(a), FieldValue::Time(b)) => a.partial_cmp(b),

            // IP address comparisons (by bytes)
            (FieldValue::Ip(a), FieldValue::Ip(b)) => {
                match (a.as_ip_addr(), b.as_ip_addr()) {
                    (IpAddr::V4(ip1), IpAddr::V4(ip2)) => ip1.octets().partial_cmp(&ip2.octets()),
                    (IpAddr::V6(ip1), IpAddr::V6(ip2)) => ip1.octets().partial_cmp(&ip2.octets()),
                    (IpAddr::V4(_), IpAddr::V6(_)) => Some(Ordering::Less), // IPv4 < IPv6
                    (IpAddr::V6(_), IpAddr::V4(_)) => Some(Ordering::Greater), // IPv6 > IPv4
                }
            }

            // Different types are not comparable
            _ => None,
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Str(s) => write!(f, "{}", s),
            FieldValue::Int(n) => write!(f, "{}", n),
            FieldValue::Uint(n) => write!(f, "{}", n),
            FieldValue::Float(fl) => write!(f, "{}", fl),
            FieldValue::Bool(b) => write!(f, "{}", b),
            FieldValue::Bytes(b) => write!(f, "Bytes[{}]", b.len()),
            FieldValue::Time(t) => write!(f, "{}", t.to_rfc3339()),
            FieldValue::Ip(ip) => write!(f, "{}", ip),
            FieldValue::Object(map) => write!(f, "Object[{}]", map.len()),
            FieldValue::Array(arr) => write!(f, "Array[{}]", arr.len()),
        }
    }
}
