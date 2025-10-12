use std::borrow::Cow;

/// A parsed command line structure for ergonomic analysis of process execution
#[derive(Debug, Clone, PartialEq)]
pub struct CommandLine<'a> {
    /// The original command line string
    raw: &'a str,

    /// The executable/program name (first argument)
    program: Cow<'a, str>,

    /// All arguments (including the program as first element)
    args: Vec<Cow<'a, str>>,

    /// Key-value parameters (e.g., --key=value, -k value)
    parameters: Vec<(Cow<'a, str>, Cow<'a, str>)>,
}

impl<'a> CommandLine<'a> {
    /// Parse a command line string into a structured representation
    pub fn parse(command_line: &'a str) -> Self {
        let args = parse_command_line_args(command_line);
        let mut ret = Self::from_args(args);
        ret.raw = command_line;
        ret
    }

    /// Get the original command line string
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Get the program/executable name
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Get all arguments (including program)
    pub fn args(&self) -> &[Cow<'a, str>] {
        &self.args
    }

    /// Get all parameters (key-value pairs)
    pub fn parameters(&self) -> &[(Cow<'a, str>, Cow<'a, str>)] {
        &self.parameters
    }

    /// Get the value of a parameter by key
    pub fn get_parameter(&self, key: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| &v[..])
    }

    /// Get the value of a parameter by key (case-insensitive)
    pub fn get_parameter_ignore_case(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_lowercase();
        self.parameters
            .iter()
            .find(|(k, _)| k.to_lowercase() == key_lower)
            .map(|(_, v)| &v[..])
    }

    /// Check if a parameter contains multiple single-character flags
    /// Returns None if the parameter doesn't exist
    /// Returns Some(Vec<char>) if the parameter exists and looks like combined flags
    /// Combined flags are detected when:
    /// - Key has multiple characters
    /// - All characters are lowercase letters
    /// - Key length is <= 4 (to avoid treating real words as flags)
    pub fn get_combined_flags(&self, key: &str) -> Option<Vec<char>> {
        if self.get_parameter(key).is_some() {
            if key.len() > 1 && key.len() <= 4 && key.chars().all(|c| c.is_ascii_lowercase()) {
                return Some(key.chars().collect());
            }
        }
        None
    }

    /// Check if a parameter appears to be combined single-character flags (has empty value and multiple chars)
    pub fn is_combined_flags(&self, key: &str) -> bool {
        self.get_combined_flags(key).is_some()
    }

    /// Create from an array of arguments
    pub fn from_args(args: Vec<Cow<'a, str>>) -> Self {
        if args.is_empty() {
            return Self {
                raw: "",
                program: Cow::Borrowed(""),
                args: Vec::new(),
                parameters: Vec::new(),
            };
        }

        let program = args[0].clone();
        let mut parameters = Vec::new();

        let mut i = 1; // Start after program name
        while i < args.len() {
            let arg = &args[i];

            if arg.starts_with("--") {
                if arg.contains('=') {
                    // --key=value format
                    if let Some(eq_pos) = arg.find('=') {
                        let key = match arg {
                            Cow::Borrowed(s) => Cow::Borrowed(&s[2..eq_pos]),
                            Cow::Owned(s) => Cow::Owned(s[2..eq_pos].to_string()),
                        };
                        let value = match arg {
                            Cow::Borrowed(s) => Cow::Borrowed(&s[eq_pos + 1..]),
                            Cow::Owned(s) => Cow::Owned(s[eq_pos + 1..].to_string()),
                        };
                        parameters.push((key, value));
                    }
                } else if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    // --key value format (only for long options)
                    let key = match arg {
                        Cow::Borrowed(s) => Cow::Borrowed(&s[2..]),
                        Cow::Owned(s) => Cow::Owned(s[2..].to_string()),
                    };
                    parameters.push((key, args[i + 1].clone()));
                    i += 1; // Skip the value argument
                } else {
                    // --key without value, store as empty string
                    let key = match arg {
                        Cow::Borrowed(s) => Cow::Borrowed(&s[2..]),
                        Cow::Owned(s) => Cow::Owned(s[2..].to_string()),
                    };
                    parameters.push((key, Cow::Borrowed("")));
                }
            } else if arg.starts_with('-') && arg.len() > 1 {
                if arg.contains('=') {
                    // -k=value format
                    if let Some(eq_pos) = arg[1..].find('=') {
                        let key = match arg {
                            Cow::Borrowed(s) => Cow::Borrowed(&s[1..eq_pos + 1]),
                            Cow::Owned(s) => Cow::Owned(s[1..eq_pos + 1].to_string()),
                        };
                        let value = match arg {
                            Cow::Borrowed(s) => Cow::Borrowed(&s[eq_pos + 2..]),
                            Cow::Owned(s) => Cow::Owned(s[eq_pos + 2..].to_string()),
                        };
                        parameters.push((key, value));
                    }
                } else if arg[1..].len() == 1 {
                    // Single character option
                    let key = match arg {
                        Cow::Borrowed(s) => Cow::Borrowed(&s[1..]),
                        Cow::Owned(s) => Cow::Owned(s[1..].to_string()),
                    };
                    if i + 1 < args.len() && !args[i + 1].starts_with('-') && args[i + 1].len() > 1
                    {
                        // Has a meaningful value following
                        parameters.push((key, args[i + 1].clone()));
                        i += 1; // Skip the value argument
                    } else {
                        // No value or single char that looks like a flag, store as empty string
                        parameters.push((key, Cow::Borrowed("")));
                    }
                } else if arg[1..].len() > 1 {
                    // Multi-character option - treat as parameter
                    let key = match arg {
                        Cow::Borrowed(s) => Cow::Borrowed(&s[1..]),
                        Cow::Owned(s) => Cow::Owned(s[1..].to_string()),
                    };
                    if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                        // Has a value following
                        parameters.push((key, args[i + 1].clone()));
                        i += 1; // Skip the value argument
                    } else {
                        // No value, store as empty string
                        parameters.push((key, Cow::Borrowed("")));
                    }
                }
            }
            // Skip non-parameter arguments since we don't track positional args anymore

            i += 1;
        }

        Self {
            raw: "",
            program,
            args: args.clone(),
            parameters,
        }
    }
}

/// Parse command line arguments with proper quote handling
fn parse_command_line_args<'a>(command_line: &'a str) -> Vec<Cow<'a, str>> {
    let mut args = Vec::new();
    let mut current_start = 0;
    let mut current_pos = 0;
    let mut needs_owned = false;
    let mut owned_arg = String::new();
    let mut in_quotes = false;
    let mut quote_char = ' ';
    let chars: Vec<char> = command_line.chars().collect();

    while current_pos < chars.len() {
        let ch = chars[current_pos];

        match ch {
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote_char = ch;
                if !needs_owned {
                    // Starting quoted section - we'll need to build owned string
                    owned_arg = command_line[current_start..current_pos].to_string();
                    needs_owned = true;
                }
                current_pos += 1;
            }
            ch if ch == quote_char && in_quotes => {
                in_quotes = false;
                quote_char = ' ';
                current_pos += 1;
            }
            ' ' | '\t' if !in_quotes => {
                // End of argument
                if current_pos > current_start || needs_owned {
                    if needs_owned {
                        if !owned_arg.is_empty() {
                            args.push(Cow::Owned(owned_arg));
                        }
                        owned_arg = String::new();
                        needs_owned = false;
                    } else {
                        let slice = &command_line[current_start..current_pos];
                        if !slice.is_empty() {
                            args.push(Cow::Borrowed(slice));
                        }
                    }
                }

                // Skip whitespace
                while current_pos < chars.len() && matches!(chars[current_pos], ' ' | '\t') {
                    current_pos += 1;
                }
                current_start = current_pos;
            }
            '\\' if in_quotes
                && current_pos + 1 < chars.len()
                && chars[current_pos + 1] == quote_char =>
            {
                // Escaped quote character
                if !needs_owned {
                    owned_arg = command_line[current_start..current_pos].to_string();
                    needs_owned = true;
                }
                owned_arg.push(quote_char);
                current_pos += 2; // Skip both backslash and quote
            }
            _ => {
                if needs_owned {
                    owned_arg.push(ch);
                }
                current_pos += 1;
            }
        }
    }

    // Handle final argument
    if current_pos > current_start || needs_owned {
        if needs_owned {
            if !owned_arg.is_empty() {
                args.push(Cow::Owned(owned_arg));
            }
        } else {
            let slice = &command_line[current_start..current_pos];
            if !slice.is_empty() {
                args.push(Cow::Borrowed(slice));
            }
        }
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command_parsing() {
        let cmd = CommandLine::parse("ls -la /home/user");

        assert_eq!(cmd.program(), "ls");
        // -la is parsed as parameter with value "/home/user"
        assert_eq!(cmd.get_parameter("la"), Some("/home/user"));
    }

    #[test]
    fn test_powershell_encoded_command() {
        let cmd = CommandLine::parse("powershell.exe -enc SGVsbG8gV29ybGQ=");

        assert_eq!(cmd.program(), "powershell.exe");
        assert_eq!(cmd.get_parameter("enc"), Some("SGVsbG8gV29ybGQ="));
    }

    #[test]
    fn test_complex_command_with_quotes() {
        let cmd =
            CommandLine::parse(r#"program --file="path with spaces.txt" -v --output /tmp/out"#);

        assert_eq!(cmd.program(), "program");
        assert_eq!(cmd.get_parameter("file"), Some("path with spaces.txt"));
        assert_eq!(cmd.get_parameter("v"), Some(""));
        assert_eq!(cmd.get_parameter("output"), Some("/tmp/out"));
    }

    #[test]
    fn test_from_args_array() {
        let args = vec![
            Cow::Borrowed("gcc"),
            Cow::Borrowed("-o"),
            Cow::Borrowed("output"),
            Cow::Borrowed("main.c"),
        ];

        let cmd = CommandLine::from_args(args);
        assert_eq!(cmd.program(), "gcc");
        assert_eq!(cmd.get_parameter("o"), Some("output"));
        // main.c is ignored since we don't track positional args
    }

    #[test]
    fn test_combined_flags_detection() {
        let cmd = CommandLine::parse("ls -la");

        assert_eq!(cmd.program(), "ls");
        assert_eq!(cmd.get_parameter("la"), Some(""));
        assert!(cmd.is_combined_flags("la"));
        assert_eq!(cmd.get_combined_flags("la"), Some(vec!['l', 'a']));

        // Test that non-combined parameters return false
        let cmd2 = CommandLine::parse("program --verbose");
        assert!(!cmd2.is_combined_flags("verbose"));
        assert_eq!(cmd2.get_combined_flags("verbose"), None);
    }
}
