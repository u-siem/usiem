use std::fmt;

/// Represents an email address extracted from a FieldValue string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email<'a> {
    raw: &'a str,
    local: &'a str,
    domain: Domain<'a>,
}

impl<'a> Email<'a> {
    /// Try to parse an email from a string slice
    pub fn try_from_str(s: &'a str) -> Result<Self, ParseError> {
        let trimmed = s.trim();

        if let Some(at_pos) = trimmed.find('@') {
            if at_pos == 0 || at_pos == trimmed.len() - 1 {
                return Err(ParseError::InvalidFormat(
                    "Email cannot start or end with @",
                ));
            }

            let local = &trimmed[..at_pos];
            let domain_str = &trimmed[at_pos + 1..];

            // Basic validation
            if local.is_empty() || domain_str.is_empty() {
                return Err(ParseError::InvalidFormat(
                    "Email local or domain part is empty",
                ));
            }

            // Parse the domain part
            let domain = Domain::try_from_str(domain_str)?;

            Ok(Email {
                raw: trimmed,
                local,
                domain,
            })
        } else {
            Err(ParseError::InvalidFormat("Email must contain @ symbol"))
        }
    }

    /// Get the full email address
    pub fn as_str(&self) -> &str {
        self.raw
    }

    /// Get the local part (before @)
    pub fn local(&self) -> &str {
        self.local
    }

    /// Get the domain part (after @) as a string
    pub fn domain(&self) -> &str {
        self.domain.as_str()
    }

    /// Get the domain as a Domain struct
    pub fn domain_parsed(&self) -> &Domain<'a> {
        &self.domain
    }

    /// Check if email is from a specific domain
    pub fn is_from_domain(&self, domain: &str) -> bool {
        self.domain.as_str().eq_ignore_ascii_case(domain)
    }

    /// Check if email ends with a specific domain suffix
    pub fn ends_with_domain(&self, suffix: &str) -> bool {
        self.domain
            .as_str()
            .to_lowercase()
            .ends_with(&suffix.to_lowercase())
    }
}

impl<'a> fmt::Display for Email<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// Represents a domain name extracted from a FieldValue string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain<'a> {
    raw: &'a str,
    parts: Vec<&'a str>,
}

impl<'a> Domain<'a> {
    /// Try to parse a domain from a string slice
    pub fn try_from_str(s: &'a str) -> Result<Self, ParseError> {
        let original = s.trim();

        if original.is_empty() {
            return Err(ParseError::InvalidFormat("Domain cannot be empty"));
        }

        if !original.contains('.') {
            return Err(ParseError::InvalidFormat(
                "Domain must contain at least one dot",
            ));
        }

        let parts: Vec<&str> = original.split('.').collect();

        // Validate parts
        for part in &parts {
            if part.is_empty() {
                return Err(ParseError::InvalidFormat("Domain parts cannot be empty"));
            }
        }

        if parts.len() < 2 {
            return Err(ParseError::InvalidFormat(
                "Domain must have at least two parts",
            ));
        }

        Ok(Domain {
            raw: original,
            parts,
        })
    }

    /// Get the full domain name
    pub fn as_str(&self) -> &str {
        self.raw
    }

    /// Get domain parts (e.g., ["example", "com"] for "example.com")
    pub fn parts(&self) -> &[&str] {
        &self.parts
    }

    /// Get the top-level domain (TLD)
    pub fn tld(&self) -> &str {
        self.parts.last().unwrap_or(&"")
    }

    /// Get the second-level domain (SLD)
    pub fn sld(&self) -> Option<&str> {
        if self.parts.len() >= 2 {
            Some(self.parts[self.parts.len() - 2])
        } else {
            None
        }
    }

    /// Get subdomains (everything except SLD and TLD)
    pub fn subdomains(&self) -> Vec<&str> {
        if self.parts.len() > 2 {
            self.parts[..self.parts.len() - 2].to_vec()
        } else {
            Vec::new()
        }
    }

    /// Check if this is a subdomain of another domain
    pub fn is_subdomain_of(&self, parent: &str) -> bool {
        self.raw
            .to_lowercase()
            .ends_with(&format!(".{}", parent.to_lowercase()))
    }

    /// Check if domain has subdomains
    pub fn has_subdomains(&self) -> bool {
        self.parts.len() > 2
    }
}

impl<'a> fmt::Display for Domain<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// Represents a URL extracted from a FieldValue string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url<'a> {
    raw: &'a str,
    scheme: Option<&'a str>,
    host: Option<Domain<'a>>,
    path: Option<&'a str>,
    query: Option<&'a str>,
}

impl<'a> Url<'a> {
    /// Try to parse a URL from a string slice (basic parsing)
    pub fn try_from_str(s: &'a str) -> Result<Self, ParseError> {
        let trimmed = s.trim();

        if trimmed.is_empty() {
            return Err(ParseError::InvalidFormat("URL cannot be empty"));
        }

        // Simple URL parsing
        let (scheme, rest) = if let Some(scheme_end) = trimmed.find("://") {
            (Some(&trimmed[..scheme_end]), &trimmed[scheme_end + 3..])
        } else {
            (None, trimmed)
        };

        let (host_and_path, query) = if let Some(query_start) = rest.find('?') {
            (&rest[..query_start], Some(&rest[query_start + 1..]))
        } else {
            (rest, None)
        };

        let (host_str, path) = if let Some(path_start) = host_and_path.find('/') {
            (
                &host_and_path[..path_start],
                Some(&host_and_path[path_start..]),
            )
        } else {
            (host_and_path, None)
        };

        // Parse the host as a domain if it's not empty
        let host = if !host_str.is_empty() {
            Some(Domain::try_from_str(host_str)?)
        } else {
            None
        };

        Ok(Url {
            raw: trimmed,
            scheme,
            host,
            path,
            query,
        })
    }

    /// Get the full URL
    pub fn as_str(&self) -> &str {
        self.raw
    }

    /// Get the scheme (e.g., "http", "https")
    pub fn scheme(&self) -> Option<&str> {
        self.scheme
    }

    /// Get the host/domain as a string
    pub fn host(&self) -> Option<&str> {
        self.host.as_ref().map(|d| d.as_str())
    }

    /// Get the path
    pub fn path(&self) -> Option<&str> {
        self.path
    }

    /// Get the query string
    pub fn query(&self) -> Option<&str> {
        self.query
    }

    /// Get the host as a Domain struct
    pub fn host_domain(&self) -> Option<&Domain<'a>> {
        self.host.as_ref()
    }

    /// Check if URL uses HTTPS
    pub fn is_https(&self) -> bool {
        self.scheme.is_some_and(|s| s.eq_ignore_ascii_case("https"))
    }

    /// Check if URL uses HTTP
    pub fn is_http(&self) -> bool {
        self.scheme.is_some_and(|s| s.eq_ignore_ascii_case("http"))
    }
}

impl<'a> fmt::Display for Url<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// Parse error for specialized types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidFormat(&'static str),
    EmptyString,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ParseError::EmptyString => write!(f, "Empty string"),
        }
    }
}

impl std::error::Error for ParseError {}
