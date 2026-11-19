//! [`EntityRef`]: the thing a finding is about (a host, a user, an IP
//! address, a device), named the same way whichever log mentioned it.
//!
//! Detection output ([`crate::processing::signal::Signal`]) lists the
//! entities it
//! concerns, so an application can add up what happened to each one (risk
//! scoring), group findings by entity, or pivot from one to everything
//! about it. This module only names and normalises entities; how risk or
//! grouping is computed is application logic.

use crate::event::field::FieldValue;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// What kind of thing an entity is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityKind {
    /// A machine, by host name.
    Host,
    /// An account, by user name.
    User,
    /// An IP address.
    Ip,
    /// A network device, by MAC address or inventory id.
    Device,
    /// A program, by name or path.
    Process,
    /// A file, by path or hash.
    File,
    /// A DNS name.
    Domain,
    /// Anything else.
    Other,
}

impl EntityKind {
    /// Every kind, in declaration order.
    pub const ALL: [EntityKind; 8] = [
        EntityKind::Host,
        EntityKind::User,
        EntityKind::Ip,
        EntityKind::Device,
        EntityKind::Process,
        EntityKind::File,
        EntityKind::Domain,
        EntityKind::Other,
    ];

    /// The lowercase name: `host`, `user`, `ip`, `device`, `process`,
    /// `file`, `domain`, `other`.
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityKind::Host => "host",
            EntityKind::User => "user",
            EntityKind::Ip => "ip",
            EntityKind::Device => "device",
            EntityKind::Process => "process",
            EntityKind::File => "file",
            EntityKind::Domain => "domain",
            EntityKind::Other => "other",
        }
    }

    /// The kind of entity an ECS-style field names, from its name alone:
    /// `source.ip` is an [`EntityKind::Ip`], `user.target.name` a
    /// [`EntityKind::User`], `host.name` a [`EntityKind::Host`],
    /// `source.mac` a [`EntityKind::Device`], `dns.question.name` a
    /// [`EntityKind::Domain`]. Unknown fields are [`EntityKind::Other`].
    ///
    /// ```
    /// use usiem::processing::entity::EntityKind;
    /// assert_eq!(EntityKind::for_field("destination.ip"), EntityKind::Ip);
    /// assert_eq!(EntityKind::for_field("user.name"), EntityKind::User);
    /// assert_eq!(EntityKind::for_field("event.code"), EntityKind::Other);
    /// ```
    pub fn for_field(field: &str) -> EntityKind {
        let last = field.rsplit('.').next().unwrap_or(field);
        if field == "ip" || last == "ip" {
            return EntityKind::Ip;
        }
        if last == "mac" || field.ends_with("device.id") {
            return EntityKind::Device;
        }
        let user_field = field == "user"
            || field.ends_with("user.name")
            || field.ends_with("user.id")
            || (field.starts_with("user.") && matches!(last, "name" | "id"));
        if user_field {
            return EntityKind::User;
        }
        if matches!(field, "host.name" | "host.hostname" | "observer.name")
            || field.ends_with(".hostname")
        {
            return EntityKind::Host;
        }
        if field.ends_with("process.name") || field.ends_with("process.executable") {
            return EntityKind::Process;
        }
        if field.starts_with("file.") {
            return EntityKind::File;
        }
        if matches!(field, "dns.question.name" | "url.domain")
            || last == "domain"
            || last == "registered_domain"
        {
            return EntityKind::Domain;
        }
        EntityKind::Other
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EntityKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EntityKind::ALL
            .into_iter()
            .find(|k| k.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| format!("unknown entity kind {s:?}"))
    }
}

/// One entity: its kind and a normalised id, so the same user, host or
/// address from different logs compares equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityRef {
    pub kind: EntityKind,
    /// Normalised: user, host, device and domain ids lowercased (a
    /// domain's trailing dot removed), IP addresses in canonical text form.
    pub id: String,
}

impl EntityRef {
    /// An entity with `id` normalised for its kind; `None` when the id is
    /// empty (or `-`, which logs use for "none").
    ///
    /// ```
    /// use usiem::processing::entity::{EntityKind, EntityRef};
    /// let a = EntityRef::new(EntityKind::User, " Alice ").unwrap();
    /// assert_eq!(a.id, "alice");
    /// let ip = EntityRef::new(EntityKind::Ip, "2001:DB8::0:1").unwrap();
    /// assert_eq!(ip.to_string(), "ip:2001:db8::1");
    /// ```
    pub fn new(kind: EntityKind, id: &str) -> Option<EntityRef> {
        let id = id.trim();
        if id.is_empty() || id == "-" {
            return None;
        }
        let id = match kind {
            EntityKind::Ip => match IpAddr::from_str(id) {
                Ok(addr) => addr.to_string(),
                Err(_) => id.to_ascii_lowercase(),
            },
            EntityKind::Domain => id.trim_end_matches('.').to_lowercase(),
            EntityKind::User | EntityKind::Host | EntityKind::Device => id.to_lowercase(),
            EntityKind::Process | EntityKind::File | EntityKind::Other => id.to_string(),
        };
        Some(EntityRef { kind, id })
    }

    /// The entity a field's value names, with the kind from
    /// [`EntityKind::for_field`]. Strings, IPs and numbers are used; other
    /// values (objects, arrays, bytes) give `None`.
    pub fn from_field(field: &str, value: &FieldValue) -> Option<EntityRef> {
        Self::from_value(EntityKind::for_field(field), value)
    }

    /// The entity `value` names as a `kind`.
    pub fn from_value(kind: EntityKind, value: &FieldValue) -> Option<EntityRef> {
        match value {
            FieldValue::Str(s) => EntityRef::new(kind, s),
            FieldValue::Ip(ip) => EntityRef::new(kind, &ip.to_string()),
            FieldValue::Int(_) | FieldValue::Uint(_) => EntityRef::new(kind, &value.to_string()),
            _ => None,
        }
    }
}

impl fmt::Display for EntityRef {
    /// `kind:id`, e.g. `user:alice`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.as_str(), self.id)
    }
}

impl FromStr for EntityRef {
    type Err = String;

    /// Parses `kind:id` (the [`fmt::Display`] form).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, id) = s
            .split_once(':')
            .ok_or_else(|| format!("{s:?}: expected kind:id"))?;
        let kind: EntityKind = kind.parse()?;
        EntityRef::new(kind, id).ok_or_else(|| format!("{s:?}: empty id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_from_field_names() {
        for (field, kind) in [
            ("source.ip", EntityKind::Ip),
            ("client.ip", EntityKind::Ip),
            ("source.mac", EntityKind::Device),
            ("source.device.id", EntityKind::Device),
            ("user.name", EntityKind::User),
            ("user.target.name", EntityKind::User),
            ("host.name", EntityKind::Host),
            ("observer.name", EntityKind::Host),
            ("process.executable", EntityKind::Process),
            ("process.parent.name", EntityKind::Other),
            ("file.hash.sha256", EntityKind::File),
            ("dns.question.name", EntityKind::Domain),
            ("client.domain", EntityKind::Domain),
            ("event.code", EntityKind::Other),
        ] {
            assert_eq!(EntityKind::for_field(field), kind, "{field}");
        }
    }

    #[test]
    fn ids_are_normalised_and_round_trip() {
        let e = EntityRef::new(EntityKind::Domain, "Evil.Example.").unwrap();
        assert_eq!(e.id, "evil.example");
        assert_eq!(EntityRef::new(EntityKind::User, "-"), None);
        let back: EntityRef = "host:WEB-01".parse().unwrap();
        assert_eq!(back.to_string(), "host:web-01");
        // An id may hold colons (IPv6, paths).
        let ip: EntityRef = "ip:2001:db8::1".parse().unwrap();
        assert_eq!(ip.kind, EntityKind::Ip);
        assert!("nonsense:x".parse::<EntityRef>().is_err());
        assert_eq!(
            EntityRef::from_field("winlog.event_id", &FieldValue::Int(4625))
                .unwrap()
                .id,
            "4625"
        );
        assert_eq!(
            EntityRef::from_field("user.name", &FieldValue::Bool(true)),
            None
        );
    }
}
