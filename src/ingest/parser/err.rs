use crate::event::field::FieldConversionError;

/// Comprehensive parsing error categorization
#[derive(Debug, Clone)]
pub enum ParsingError {
    /// Parser format error - log matches parser but has invalid format
    FormatError {
        message: String,
        position: Option<usize>,
        expected_format: Option<&'static str>,
        actual_sample: Option<String>,
    },
    /// Parser implementation error - bug in parser code
    ParserError {
        message: String,
        parser_id: &'static str,
        context: Option<String>,
    },
    /// Feature not implemented yet
    NotImplemented {
        feature: &'static str,
        parser_id: &'static str,
    },
    /// Field extraction failed
    FieldExtractionError {
        field_name: &'static str,
        reason: String,
    },
}

/// Reasons for log discard
#[derive(Debug, Clone)]
pub enum DiscardReason {
    /// Log is noise/spam
    Noise,
    /// Log exceeds size limits
    TooLarge(usize),
    /// Log is duplicate
    Duplicate,
    /// Log is from filtered source
    FilteredSource,
    /// Custom discard reason
    Custom(String),
}

impl ParsingError {
    pub fn format_error(message: impl Into<String>) -> Self {
        Self::FormatError {
            message: message.into(),
            position: None,
            expected_format: None,
            actual_sample: None,
        }
    }

    pub fn parser_error(message: impl Into<String>, parser_id: &'static str) -> Self {
        Self::ParserError {
            message: message.into(),
            parser_id,
            context: None,
        }
    }

    pub fn not_implemented(feature: &'static str, parser_id: &'static str) -> Self {
        Self::NotImplemented { feature, parser_id }
    }
}

impl std::fmt::Display for ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsingError::FormatError {
                message,
                position,
                expected_format,
                actual_sample,
            } => {
                write!(f, "format error: {}", message)?;
                if let Some(pos) = position {
                    write!(f, " (at position {})", pos)?;
                }
                if let Some(expected) = expected_format {
                    write!(f, " (expected format: {})", expected)?;
                }
                if let Some(sample) = actual_sample {
                    write!(f, " (got: {:?})", sample)?;
                }
                Ok(())
            }
            ParsingError::ParserError {
                message,
                parser_id,
                context,
            } => {
                write!(f, "parser '{}' error: {}", parser_id, message)?;
                if let Some(ctx) = context {
                    write!(f, " ({})", ctx)?;
                }
                Ok(())
            }
            ParsingError::NotImplemented { feature, parser_id } => {
                write!(f, "parser '{}' does not implement: {}", parser_id, feature)
            }
            ParsingError::FieldExtractionError { field_name, reason } => {
                write!(f, "failed to extract field '{}': {}", field_name, reason)
            }
        }
    }
}

impl std::error::Error for ParsingError {}

/// Lets a parser body use `?` on [`crate::event::field::FieldValue::extract`]
/// (or any `TryFrom<&FieldValue, Error = FieldConversionError>` call) inside a
/// function returning `Result<_, ParsingError>`. The conversion failure is
/// reported as a [`ParsingError::FormatError`], since a field that doesn't
/// convert to the expected type is a format problem with the input, not a
/// bug in the parser.
impl From<FieldConversionError> for ParsingError {
    fn from(err: FieldConversionError) -> Self {
        ParsingError::FormatError {
            message: err.to_string(),
            position: None,
            expected_format: None,
            actual_sample: None,
        }
    }
}

impl std::fmt::Display for DiscardReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscardReason::Noise => write!(f, "discarded as noise"),
            DiscardReason::TooLarge(size) => {
                write!(f, "discarded: log exceeds size limit ({} bytes)", size)
            }
            DiscardReason::Duplicate => write!(f, "discarded as duplicate"),
            DiscardReason::FilteredSource => write!(f, "discarded: source is filtered"),
            DiscardReason::Custom(reason) => write!(f, "discarded: {}", reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::FieldValue;

    #[test]
    fn test_field_conversion_error_converts_via_question_mark() {
        fn extract_severity(value: &FieldValue) -> Result<i64, ParsingError> {
            // `FieldConversionError` -> `ParsingError` via `?`, not a manual `.map_err`.
            let severity: i64 = value.extract()?;
            Ok(severity)
        }

        let err = extract_severity(&FieldValue::str("not a number")).unwrap_err();
        assert!(matches!(err, ParsingError::FormatError { .. }));
    }

    #[test]
    fn test_parsing_error_display() {
        let err = ParsingError::format_error("bad timestamp");
        assert_eq!(err.to_string(), "format error: bad timestamp");

        let err = ParsingError::parser_error("regex did not match", "apache_common");
        assert_eq!(
            err.to_string(),
            "parser 'apache_common' error: regex did not match"
        );

        let err = ParsingError::not_implemented("gzip decompression", "json");
        assert_eq!(
            err.to_string(),
            "parser 'json' does not implement: gzip decompression"
        );

        let err = ParsingError::FieldExtractionError {
            field_name: "client.ip",
            reason: "not a valid IP".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to extract field 'client.ip': not a valid IP"
        );
    }

    #[test]
    fn test_parsing_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ParsingError::format_error("bad timestamp"));
        assert_eq!(err.to_string(), "format error: bad timestamp");
    }

    #[test]
    fn test_discard_reason_display() {
        assert_eq!(DiscardReason::Noise.to_string(), "discarded as noise");
        assert_eq!(
            DiscardReason::TooLarge(1024).to_string(),
            "discarded: log exceeds size limit (1024 bytes)"
        );
        assert_eq!(
            DiscardReason::Duplicate.to_string(),
            "discarded as duplicate"
        );
        assert_eq!(
            DiscardReason::FilteredSource.to_string(),
            "discarded: source is filtered"
        );
        assert_eq!(
            DiscardReason::Custom("rate limited".to_string()).to_string(),
            "discarded: rate limited"
        );
    }
}
