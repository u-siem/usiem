use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Specialized IP field supporting both IPv4 and IPv6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ip {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl FromStr for Ip {
    type Err = IpParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Ok(Ip::V4(ip)),
            Ok(IpAddr::V6(ip)) => Ok(Ip::V6(ip)),
            Err(_) => Err(IpParseError::InvalidFormat),
        }
    }
}

impl Ip {
    /// Get as IpAddr
    pub fn as_ip_addr(&self) -> IpAddr {
        match self {
            Ip::V4(ip) => IpAddr::V4(*ip),
            Ip::V6(ip) => IpAddr::V6(*ip),
        }
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Ip::V4(_))
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Ip::V6(_))
    }

    /// Check if this is a private/internal IP
    pub fn is_private(&self) -> bool {
        match self {
            Ip::V4(ip) => ip.is_private(),
            Ip::V6(ip) => {
                // IPv6 private ranges: fc00::/7, fe80::/10
                let octets = ip.octets();
                (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
            }
        }
    }

    /// Check if this is a loopback address
    pub fn is_loopback(&self) -> bool {
        self.as_ip_addr().is_loopback()
    }

    /// Check if this is a multicast address
    pub fn is_multicast(&self) -> bool {
        self.as_ip_addr().is_multicast()
    }
}

#[derive(Debug, Clone)]
pub enum IpParseError {
    InvalidFormat,
}

impl std::fmt::Display for IpParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpParseError::InvalidFormat => write!(f, "Invalid IP address format"),
        }
    }
}
impl std::error::Error for IpParseError {}

impl From<Ipv4Addr> for Ip {
    fn from(ip: Ipv4Addr) -> Self {
        Ip::V4(ip)
    }
}

impl From<Ipv6Addr> for Ip {
    fn from(ip: Ipv6Addr) -> Self {
        Ip::V6(ip)
    }
}

impl From<IpAddr> for Ip {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Ip::V4(ip),
            IpAddr::V6(ip) => Ip::V6(ip),
        }
    }
}

impl std::fmt::Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ip::V4(ip) => write!(f, "{}", ip),
            Ip::V6(ip) => write!(f, "{}", ip),
        }
    }
}
