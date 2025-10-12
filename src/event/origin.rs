use crate::event::field::Ip;
use std::fmt;

/// Represents the origin/source of an event
/// Used by both RawEvent and core Event structures
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Event originated from a specific IP address (network sources)
    Ip(Ip),
    /// Event originated from a hostname (syslog, remote systems)
    Hostname(String),
    /// Event originated from a collector (EDR, agent, forwarder, etc.)
    Collector(String),
    /// Event originated from a file path (local file reading)
    File(String),
    /// Event originated from a container/pod (Docker, Kubernetes)
    Container {
        id: String,
        name: Option<String>,
        image: Option<String>,
    },
}

impl Origin {
    /// Create Origin from a simple string source
    /// Attempts to parse as IP, otherwise treats as hostname
    pub fn from_source_string(source: &str) -> Self {
        if let Ok(ip_addr) = source.parse::<std::net::IpAddr>() {
            Origin::Ip(Ip::from(ip_addr))
        } else if source.starts_with('/') || source.contains('\\') || source.contains(".log") {
            // Looks like a file path
            Origin::File(source.to_string())
        } else {
            // Default to hostname
            Origin::Hostname(source.to_string())
        }
    }

    /// Create an Origin from an IP address
    pub fn from_ip(ip: Ip) -> Self {
        Origin::Ip(ip)
    }

    /// Create an Origin from a hostname
    pub fn from_hostname<S: Into<String>>(hostname: S) -> Self {
        Origin::Hostname(hostname.into())
    }

    /// Create an Origin from a collector ID
    pub fn from_collector<S: Into<String>>(collector_id: S) -> Self {
        Origin::Collector(collector_id.into())
    }

    /// Create an Origin from a file path
    pub fn from_file<S: Into<String>>(path: S) -> Self {
        Origin::File(path.into())
    }

    /// Get a string representation of this origin for display purposes
    pub fn as_string(&self) -> String {
        match self {
            Origin::Ip(ip) => ip.to_string(),
            Origin::Hostname(hostname) => hostname.clone(),
            Origin::Collector(collector) => collector.clone(),
            Origin::File(path) => path.clone(),
            Origin::Container { id, name, .. } => {
                if let Some(name) = name {
                    format!("container:{}", name)
                } else {
                    format!("container:{}", id)
                }
            }
        }
    }

    /// Check if this origin represents a network source
    pub fn is_network_source(&self) -> bool {
        matches!(self, Origin::Ip(_))
    }

    /// Check if this origin represents a local source
    pub fn is_local_source(&self) -> bool {
        matches!(self, Origin::File(_) | Origin::Container { .. })
    }

    /// Get a reference to the string content if possible
    pub fn as_string_ref(&self) -> Option<&str> {
        match self {
            Origin::Ip(_) => None,
            Origin::Hostname(hostname) => Some(hostname),
            Origin::Collector(collector) => Some(collector),
            Origin::File(path) => Some(path),
            Origin::Container {
                name: Some(name), ..
            } => Some(name),
            Origin::Container { id, name: None, .. } => Some(id),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl From<std::net::IpAddr> for Origin {
    fn from(ip: std::net::IpAddr) -> Self {
        Origin::Ip(Ip::from(ip))
    }
}

impl From<&str> for Origin {
    fn from(source: &str) -> Self {
        Origin::from_source_string(source)
    }
}

impl From<String> for Origin {
    fn from(source: String) -> Self {
        Origin::from_source_string(&source)
    }
}
