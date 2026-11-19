//! [`Signal`]: an event (or cluster of events) evaluated against context or
//! threat intelligence and flagged as potentially suspicious — not yet an
//! explicit alarm.
//!
//! A `Signal` is deliberately *not* analyst-facing on its own: it states a
//! fact ("this looked suspicious"), not a judgment that a human should look
//! at it right now. That judgment is [`crate::processing::incident::Incident`]'s
//! job — an independent, application-driven aggregate built from `Signal`s
//! and/or raw events once a rule decides the evidence is significant enough.
//! See that module's docs for how the two relate.
//!
//! `Signal`s are typically produced by application code that implements its
//! own correlation/detection logic (e.g. a time-windowed threshold counter —
//! this crate deliberately has no correlation API of its own), and/or by
//! consulting enrichment lookups such as
//! [`crate::processing::enrichment::providers::ThreatIntelDataset`]/
//! [`crate::processing::enrichment::providers::GeoIpDataset`] — the kind of
//! "context or threat intelligence" a `Signal` is evaluated against.

use crate::event::core::RawData;
use crate::event::field::{FieldValue, Text, Timestamp};
use crate::event::hash::StableHasher;
use crate::event::{Event, EventId, Origin};
use crate::processing::entity::EntityRef;
use crate::processing::message::LocalizedMessage;
use crate::processing::rating::RiskScore;
use std::collections::HashMap;

// Moved to `rating` so enrichment types share them; re-exported here so
// `processing::signal::{Severity, Confidence}` keeps working.
pub use crate::processing::rating::{Confidence, Severity};

/// A lightweight pointer back to a raw [`Event`] — its [`EventId`] plus
/// its [`Timestamp`], not the full event, so referencing it doesn't
/// duplicate raw payloads. Used by [`Signal::source_events`] and
/// [`crate::processing::incident::Evidence::Event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventRef {
    pub id: EventId,
    pub timestamp: Timestamp,
}

impl From<&Event> for EventRef {
    fn from(event: &Event) -> Self {
        Self {
            id: event.id(),
            timestamp: event.original_time(),
        }
    }
}

/// Stable content-hash identifier for a [`Signal`]. Like [`EventId`],
/// computed on demand by [`Signal::id`] from identifying fields rather than
/// stored on the struct — it can never go stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignalId(u64);

impl SignalId {
    /// The identifier as a raw `u64`.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SignalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// An event (or cluster of events) evaluated against context or threat
/// intelligence and flagged as potentially suspicious — not yet an explicit
/// alarm. See the module docs for how this relates to
/// [`crate::processing::incident::Incident`].
///
/// # Example
///
/// ```
/// use usiem::processing::message::LocalizedMessage;
/// use usiem::processing::signal::{Confidence, Severity, Signal};
/// use usiem::event::field::Timestamp;
///
/// let message = LocalizedMessage::new(
///     "auth.brute_force_threshold",
///     "en-US",
///     "3 failed logins for alice within 60s",
/// )
/// .with_param("count", 3);
///
/// let signal = Signal::new(
///     "repeated_failed_login",
///     "alice",
///     Severity::High,
///     Confidence::new(80),
///     message,
///     Timestamp::from_secs(1_700_000_000),
/// )
/// .with_techniques(["T1110"]);
///
/// assert_eq!(signal.severity, Severity::High);
/// assert_eq!(signal.techniques, vec!["T1110"]);
/// ```
#[derive(Debug, Clone)]
pub struct Signal {
    /// Name of the rule/logic that produced this signal.
    pub rule_name: Text,
    /// The correlation key this signal fired for (a username, source IP, etc).
    pub key: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// MITRE ATT&CK technique ids this signal maps to, e.g. `"T1110"`.
    pub techniques: Vec<Text>,
    /// The event(s) this signal was evaluated from.
    pub source_events: Vec<EventRef>,
    /// Supporting context (e.g. copied from a threat-intel/GeoIP lookup)
    /// backing the "suspicious" judgment. Independent of `message.params`.
    pub context: HashMap<String, FieldValue>,
    pub message: LocalizedMessage,
    /// When the underlying condition was detected.
    pub observed_at: Timestamp,
    /// The hosts, users, addresses or devices this signal is about.
    pub entities: Vec<EntityRef>,
    /// How much this signal adds to each of [`Signal::entities`]' risk.
    pub risk: Option<RiskScore>,
}

impl Signal {
    /// Create a new signal with no techniques, source events, or context.
    pub fn new(
        rule_name: impl Into<Text>,
        key: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        message: LocalizedMessage,
        observed_at: Timestamp,
    ) -> Self {
        Self {
            rule_name: rule_name.into(),
            key: key.into(),
            severity,
            confidence,
            techniques: Vec::new(),
            source_events: Vec::new(),
            context: HashMap::new(),
            message,
            observed_at,
            entities: Vec::new(),
            risk: None,
        }
    }

    /// Attach the entities this signal is about; chainable.
    pub fn with_entities(mut self, entities: impl IntoIterator<Item = EntityRef>) -> Self {
        self.entities.extend(entities);
        self
    }

    /// Set the risk this signal adds to each of its entities; chainable.
    pub fn with_risk(mut self, risk: RiskScore) -> Self {
        self.risk = Some(risk);
        self
    }

    /// Attach MITRE ATT&CK technique ids; chainable.
    pub fn with_techniques<T: Into<Text>>(
        mut self,
        techniques: impl IntoIterator<Item = T>,
    ) -> Self {
        self.techniques
            .extend(techniques.into_iter().map(Into::into));
        self
    }

    /// Attach the event(s) this signal was evaluated from; chainable.
    pub fn with_source_events(mut self, events: impl IntoIterator<Item = EventRef>) -> Self {
        self.source_events.extend(events);
        self
    }

    /// Attach one piece of supporting context; chainable.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// A stable identifier derived from `rule_name`, `key`, `observed_at`,
    /// and `message.template_id` — the fields that identify *which fact*
    /// this signal states. Deliberately excludes `severity`/`confidence`/
    /// `context`, which could shift slightly between equivalent
    /// re-evaluations without changing what actually happened.
    pub fn id(&self) -> SignalId {
        let mut hasher = StableHasher::new();
        hasher.write_str(&self.rule_name);
        hasher.write_str(&self.key);
        hasher.write_timestamp(self.observed_at);
        hasher.write_str(&self.message.template_id);
        SignalId(hasher.finish())
    }

    /// `FieldValue::Object` form of every field, including `observed_at` —
    /// used both by [`Signal::into_event`] (which strips `observed_at` back
    /// out, since it plays the role of the resulting event's
    /// `original_time`) and by
    /// [`crate::processing::incident::Evidence::Signal`] when embedding this
    /// signal as evidence inside an `Incident`.
    pub(crate) fn to_field_value(&self) -> FieldValue {
        let mut object = HashMap::new();
        object.insert(Text::from("id"), FieldValue::string(self.id().to_string()));
        object.insert(
            Text::from("rule_name"),
            FieldValue::Str(self.rule_name.clone()),
        );
        object.insert(Text::from("key"), FieldValue::string(self.key.clone()));
        object.insert(
            Text::from("severity"),
            FieldValue::str(self.severity.as_str()),
        );
        object.insert(
            Text::from("confidence"),
            FieldValue::uint(self.confidence.as_percent() as u64),
        );
        object.insert(
            Text::from("techniques"),
            FieldValue::Array(
                self.techniques
                    .iter()
                    .cloned()
                    .map(FieldValue::Str)
                    .collect(),
            ),
        );
        object.insert(
            Text::from("source_events"),
            FieldValue::Array(
                self.source_events
                    .iter()
                    .map(|event_ref| {
                        let mut object = HashMap::new();
                        object.insert(
                            Text::from("id"),
                            FieldValue::string(event_ref.id.to_string()),
                        );
                        object.insert(
                            Text::from("timestamp"),
                            FieldValue::Time(event_ref.timestamp),
                        );
                        FieldValue::Object(object)
                    })
                    .collect(),
            ),
        );
        object.insert(
            Text::from("context"),
            FieldValue::Object(
                self.context
                    .iter()
                    .map(|(k, v)| (Text::from(k.clone()), v.clone()))
                    .collect(),
            ),
        );
        object.insert(Text::from("message"), self.message.to_field_value());
        object.insert(
            Text::from("observed_at"),
            FieldValue::Time(self.observed_at),
        );
        if !self.entities.is_empty() {
            object.insert(Text::from("entities"), entities_field(&self.entities));
        }
        if let Some(risk) = self.risk {
            object.insert(
                Text::from("risk"),
                FieldValue::uint(u64::from(risk.points())),
            );
        }
        FieldValue::Object(object)
    }

    /// Convert this signal into a [`Event`], so it can be shipped
    /// through the same [`crate::processing::sink::Sink`] used for ordinary
    /// events. Fields are namespaced under `signal.*`; `original_time` is
    /// set to `observed_at`.
    pub fn into_event(self) -> Event {
        let observed_at = self.observed_at;
        let text = self.message.text.clone();
        let mut fields = match self.to_field_value() {
            FieldValue::Object(fields) => fields,
            _ => unreachable!("Signal::to_field_value always returns an Object"),
        };
        fields.remove("observed_at"); // carried as the event's original_time instead

        let mut event = Event::new(
            Timestamp::now(),
            observed_at,
            Origin::from_hostname("usiem-correlation"),
            RawData::from_text(text),
        );
        event.add_field("event_type", FieldValue::str("signal"));
        for (key, value) in fields {
            event.add_field(format!("signal.{key}"), value);
        }
        event
    }
}

/// Entities as an array of `{type, id}` objects (`signal.entities`,
/// `incident.entities`).
pub(crate) fn entities_field(entities: &[EntityRef]) -> FieldValue {
    FieldValue::Array(
        entities
            .iter()
            .map(|e| {
                let mut object = HashMap::new();
                object.insert(Text::from("type"), FieldValue::str(e.kind.as_str()));
                object.insert(Text::from("id"), FieldValue::string(e.id.clone()));
                FieldValue::Object(object)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> LocalizedMessage {
        LocalizedMessage::new(
            "auth.brute_force_threshold",
            "en-US",
            "3 failed logins for alice within 60s",
        )
        .with_param("count", 3)
    }

    #[test]
    fn test_confidence_clamps_to_100() {
        assert_eq!(Confidence::new(150).as_percent(), 100);
        assert_eq!(Confidence::new(42).as_percent(), 42);
    }

    #[test]
    fn test_signal_id_is_stable_for_identical_content() {
        let observed_at = Timestamp::from_secs(1_700_000_000);
        let a = Signal::new(
            "repeated_failed_login",
            "alice",
            Severity::High,
            Confidence::new(80),
            sample_message(),
            observed_at,
        );
        let b = a.clone();

        assert_eq!(a.id(), b.id());
    }

    /// Pins the exact id: signal ids are stored with alerts, so a change
    /// here breaks stored links. Revert the hashing change, don't update this.
    #[test]
    fn test_signal_id_golden_value() {
        let signal = Signal::new(
            "repeated_failed_login",
            "alice",
            Severity::High,
            Confidence::new(80),
            sample_message(),
            Timestamp::from_secs(1_700_000_000),
        );
        assert_eq!(signal.id().to_string(), "93cd9355d40edbe1");
    }

    #[test]
    fn test_signal_id_differs_for_different_key() {
        let observed_at = Timestamp::from_secs(1_700_000_000);
        let a = Signal::new(
            "repeated_failed_login",
            "alice",
            Severity::High,
            Confidence::new(80),
            sample_message(),
            observed_at,
        );
        let b = Signal::new(
            "repeated_failed_login",
            "bob",
            Severity::High,
            Confidence::new(80),
            sample_message(),
            observed_at,
        );

        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn test_signal_into_event_carries_fields() {
        let observed_at = Timestamp::from_secs(1_700_000_000);
        let source_event = Event::new(
            Timestamp::now(),
            observed_at,
            Origin::from_hostname("test-host"),
            RawData::from_text("401 login attempt"),
        );
        let signal = Signal::new(
            "repeated_failed_login",
            "alice",
            Severity::High,
            Confidence::new(80),
            sample_message(),
            observed_at,
        )
        .with_techniques(["T1110"])
        .with_source_events([EventRef::from(&source_event)])
        .with_context("threat_intel.source", FieldValue::str("AbuseIPDB"));

        let event = signal.into_event();

        assert_eq!(
            event.get_field("event_type").and_then(|f| f.as_str()),
            Some("signal")
        );
        assert_eq!(
            event.get_field("signal.rule_name").and_then(|f| f.as_str()),
            Some("repeated_failed_login")
        );
        assert_eq!(
            event.get_field("signal.key").and_then(|f| f.as_str()),
            Some("alice")
        );
        assert_eq!(
            event.get_field("signal.severity").and_then(|f| f.as_str()),
            Some("high")
        );
        assert_eq!(
            event
                .get_field("signal.confidence")
                .and_then(|f| f.as_u64()),
            Some(80)
        );
        assert!(matches!(
            event.get_field("signal.techniques"),
            Some(FieldValue::Array(items)) if items.len() == 1
        ));
        assert!(matches!(
            event.get_field("signal.source_events"),
            Some(FieldValue::Array(items)) if items.len() == 1
        ));
        assert!(matches!(
            event.get_field("signal.context"),
            Some(FieldValue::Object(_))
        ));
        assert!(matches!(
            event.get_field("signal.message"),
            Some(FieldValue::Object(_))
        ));
        assert_eq!(event.get_field("signal.observed_at"), None);
        assert_eq!(event.original_time(), observed_at);
    }
}
