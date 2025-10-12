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
            parser_id: parser_id,
            context: None,
        }
    }

    pub fn not_implemented(feature: &'static str, parser_id: &'static str) -> Self {
        Self::NotImplemented {
            feature: feature,
            parser_id: parser_id,
        }
    }
}
