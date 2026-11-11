//! [`Incident`]: an analyst-facing aggregate of [`Evidence`] (raw events
//! and/or [`Signal`](crate::processing::signal::Signal)s) that some
//! application-defined rule has judged significant enough to surface.
//!
//! `Incident` is **independent of `Signal`**: this crate ships no "N
//! signals ⇒ Incident" aggregation primitive, deliberately — correlation
//! and detection logic is entirely the consuming application's
//! responsibility. Write your own rule in plain Rust, and construct an
//! `Incident` directly once your rule decides some collection of evidence
//! is significant.
//!
//! `Incident` shares almost every field with `Signal` — each an independent
//! judgment, not copied from the other (three low-confidence `Signal`s
//! corroborating each other is exactly what can make an `Incident`
//! high-confidence even though no single `Signal` was). The real
//! differences are [`Incident::evidence`] itself, and a time *range*
//! (`first_seen`/`last_seen`) in place of `Signal`'s single `observed_at` —
//! reflecting that an `Incident` can grow after creation via
//! [`Incident::add_evidence`], while a `Signal` is built once and is done.

use crate::event::core::RawData;
use crate::event::field::{FieldValue, Text, Timestamp};
use crate::event::{CoreEvent, Origin};
use crate::processing::entity::EntityRef;
use crate::processing::message::LocalizedMessage;
use crate::processing::signal::{Confidence, EventRef, Severity, Signal};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// One piece of evidence backing an [`Incident`]: either a reference to a
/// raw ingested event, or an embedded [`Signal`].
///
/// `Signal` is boxed: it's far larger than `EventRef` (which is just an id
/// plus a timestamp), and `Evidence` is sized to its largest variant — an
/// unboxed `Signal` would make every `EventRef`-backed entry in an
/// `Incident`'s `evidence: Vec<Evidence>` pay for space it doesn't use.
#[derive(Debug, Clone)]
pub enum Evidence {
    Event(EventRef),
    Signal(Box<Signal>),
}

impl Evidence {
    /// The moment this evidence is anchored to, used by
    /// [`Incident::add_evidence`] to extend `last_seen`.
    fn timestamp(&self) -> Timestamp {
        match self {
            Evidence::Event(event_ref) => event_ref.timestamp,
            Evidence::Signal(signal) => signal.observed_at,
        }
    }

    /// `FieldValue::Object` form: `{"kind": "event", id, timestamp}` or
    /// `{"kind": "signal", ...all of Signal::to_field_value...}`.
    fn to_field_value(&self) -> FieldValue {
        let mut object = HashMap::new();
        match self {
            Evidence::Event(event_ref) => {
                object.insert(Text::from("kind"), FieldValue::str("event"));
                object.insert(
                    Text::from("id"),
                    FieldValue::string(event_ref.id.to_string()),
                );
                object.insert(
                    Text::from("timestamp"),
                    FieldValue::Time(event_ref.timestamp),
                );
            }
            Evidence::Signal(signal) => {
                object.insert(Text::from("kind"), FieldValue::str("signal"));
                if let FieldValue::Object(signal_fields) = signal.to_field_value() {
                    object.extend(signal_fields);
                }
            }
        }
        FieldValue::Object(object)
    }
}

impl From<EventRef> for Evidence {
    fn from(event_ref: EventRef) -> Self {
        Evidence::Event(event_ref)
    }
}

impl From<&CoreEvent> for Evidence {
    fn from(event: &CoreEvent) -> Self {
        Evidence::Event(event.into())
    }
}

impl From<Signal> for Evidence {
    fn from(signal: Signal) -> Self {
        Evidence::Signal(Box::new(signal))
    }
}

/// Stable content-hash identifier for an [`Incident`]. Like [`SignalId`],
/// computed on demand by [`Incident::id`] from fields fixed at creation —
/// not from `evidence`, which grows over the incident's life via
/// [`Incident::add_evidence`] — so the id stays a valid, stable
/// cross-reference throughout.
///
/// [`SignalId`]: crate::processing::signal::SignalId
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IncidentId(u64);

impl IncidentId {
    /// The identifier as a raw `u64`.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for IncidentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// An analyst-facing aggregate: a named collection of [`Evidence`] that some
/// application-defined rule judged significant enough to surface. See the
/// module docs for how this relates to
/// [`Signal`](crate::processing::signal::Signal).
///
/// # Example
///
/// ```
/// use usiem::processing::incident::Incident;
/// use usiem::processing::message::LocalizedMessage;
/// use usiem::processing::signal::{Confidence, Severity, Signal};
/// use usiem::event::field::Timestamp;
///
/// let observed_at = Timestamp::from_secs(1_700_000_000);
/// let signal = Signal::new(
///     "repeated_failed_login",
///     "alice",
///     Severity::High,
///     Confidence::new(80),
///     LocalizedMessage::new("auth.brute_force_threshold", "en-US", "3 failed logins for alice"),
///     observed_at,
/// );
///
/// let mut incident = Incident::new(
///     "brute_force_campaign",
///     "alice",
///     Severity::Critical,
///     Confidence::new(95),
///     LocalizedMessage::new("auth.brute_force_campaign", "en-US", "Sustained brute force against alice"),
///     observed_at,
/// )
/// .with_techniques(["T1110"]);
/// incident.add_evidence(signal);
///
/// assert_eq!(incident.evidence.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct Incident {
    /// Name of the rule/logic that produced this incident.
    pub rule_name: Text,
    /// The correlation key this incident is about (a username, source IP, etc).
    pub key: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// MITRE ATT&CK technique ids this incident maps to, e.g. `"T1110"`.
    pub techniques: Vec<Text>,
    /// Supporting context independent of any single piece of evidence.
    pub context: HashMap<String, FieldValue>,
    pub message: LocalizedMessage,
    pub evidence: Vec<Evidence>,
    /// The hosts, users, addresses or devices this incident is about.
    pub entities: Vec<EntityRef>,
    /// When the earliest evidence occurred / this incident was opened.
    pub first_seen: Timestamp,
    /// When the most recent evidence occurred; extended by [`Incident::add_evidence`].
    pub last_seen: Timestamp,
}

impl Incident {
    /// Create a new incident with no evidence, techniques, or context.
    pub fn new(
        rule_name: impl Into<Text>,
        key: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        message: LocalizedMessage,
        opened_at: Timestamp,
    ) -> Self {
        Self {
            rule_name: rule_name.into(),
            key: key.into(),
            severity,
            confidence,
            techniques: Vec::new(),
            context: HashMap::new(),
            message,
            evidence: Vec::new(),
            entities: Vec::new(),
            first_seen: opened_at,
            last_seen: opened_at,
        }
    }

    /// Attach the entities this incident is about; chainable. Repeats are
    /// kept once.
    pub fn with_entities(mut self, entities: impl IntoIterator<Item = EntityRef>) -> Self {
        for e in entities {
            if !self.entities.contains(&e) {
                self.entities.push(e);
            }
        }
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

    /// Attach one piece of supporting context; chainable.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Append one piece of evidence; chainable like
    /// [`crate::processing::pipeline::Pipeline::add_stage`]. Extends
    /// `last_seen` forward if the evidence's own timestamp is newer.
    pub fn add_evidence(&mut self, evidence: impl Into<Evidence>) -> &mut Self {
        let evidence = evidence.into();
        let timestamp = evidence.timestamp();
        if timestamp.is_after(&self.last_seen) {
            self.last_seen = timestamp;
        }
        self.evidence.push(evidence);
        self
    }

    /// A stable identifier derived from `rule_name`, `key`, and `first_seen`
    /// — fixed at creation, so it doesn't change as `evidence` grows.
    pub fn id(&self) -> IncidentId {
        let mut hasher = DefaultHasher::new();
        self.rule_name.hash(&mut hasher);
        self.key.hash(&mut hasher);
        self.first_seen.as_nanos().hash(&mut hasher);
        IncidentId(hasher.finish())
    }

    /// Convert this incident into a [`CoreEvent`], so it can be shipped
    /// through the same [`crate::processing::sink::Sink`] used for ordinary
    /// events and `Signal`s. Fields are namespaced under `incident.*`;
    /// `original_time` is set to `first_seen`.
    pub fn into_event(self) -> CoreEvent {
        let id = self.id();
        let first_seen = self.first_seen;
        let last_seen = self.last_seen;
        let text = self.message.text.clone();
        let evidence_field =
            FieldValue::Array(self.evidence.iter().map(Evidence::to_field_value).collect());
        let message_field = self.message.to_field_value();
        let context_field = FieldValue::Object(
            self.context
                .into_iter()
                .map(|(k, v)| (Text::from(k), v))
                .collect(),
        );
        let techniques_field =
            FieldValue::Array(self.techniques.into_iter().map(FieldValue::Str).collect());

        let mut event = CoreEvent::new(
            Timestamp::now(),
            first_seen,
            Origin::from_hostname("usiem-correlation"),
            RawData::from_text(text),
        );
        event.add_field("event_type".to_string(), FieldValue::str("incident"));
        event.add_field(
            "incident.id".to_string(),
            FieldValue::string(id.to_string()),
        );
        event.add_field(
            "incident.rule_name".to_string(),
            FieldValue::Str(self.rule_name),
        );
        event.add_field("incident.key".to_string(), FieldValue::string(self.key));
        event.add_field(
            "incident.severity".to_string(),
            FieldValue::str(self.severity.as_str()),
        );
        event.add_field(
            "incident.confidence".to_string(),
            FieldValue::uint(self.confidence.as_percent() as u64),
        );
        event.add_field("incident.techniques".to_string(), techniques_field);
        event.add_field("incident.context".to_string(), context_field);
        event.add_field("incident.message".to_string(), message_field);
        event.add_field("incident.evidence".to_string(), evidence_field);
        if !self.entities.is_empty() {
            event.add_field(
                "incident.entities".to_string(),
                crate::processing::signal::entities_field(&self.entities),
            );
        }
        event.add_field(
            "incident.last_seen".to_string(),
            FieldValue::Time(last_seen),
        );
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::field::Timestamp;

    fn sample_message(template_id: &'static str, text: &'static str) -> LocalizedMessage {
        LocalizedMessage::new(template_id, "en-US", text)
    }

    fn sample_signal(key: &str, observed_at: Timestamp) -> Signal {
        Signal::new(
            "repeated_failed_login",
            key,
            Severity::High,
            Confidence::new(80),
            sample_message("auth.brute_force_threshold", "3 failed logins"),
            observed_at,
        )
    }

    #[test]
    fn test_incident_id_is_stable_and_independent_of_evidence() {
        let opened_at = Timestamp::from_secs(1_700_000_000);
        let mut incident = Incident::new(
            "brute_force_campaign",
            "alice",
            Severity::Critical,
            Confidence::new(95),
            sample_message("auth.brute_force_campaign", "Sustained brute force"),
            opened_at,
        );
        let id_before = incident.id();

        incident.add_evidence(sample_signal("alice", opened_at.add_secs(10)));

        assert_eq!(id_before, incident.id());
    }

    #[test]
    fn test_add_evidence_extends_last_seen_forward_only() {
        let opened_at = Timestamp::from_secs(1_700_000_000);
        let mut incident = Incident::new(
            "brute_force_campaign",
            "alice",
            Severity::Critical,
            Confidence::new(95),
            sample_message("auth.brute_force_campaign", "Sustained brute force"),
            opened_at,
        );

        incident.add_evidence(sample_signal("alice", opened_at.add_secs(30)));
        assert_eq!(incident.last_seen, opened_at.add_secs(30));

        // An earlier piece of evidence must not move last_seen backwards.
        incident.add_evidence(sample_signal("alice", opened_at.add_secs(5)));
        assert_eq!(incident.last_seen, opened_at.add_secs(30));
        assert_eq!(incident.first_seen, opened_at);
    }

    #[test]
    fn test_incident_into_event_carries_evidence() {
        let opened_at = Timestamp::from_secs(1_700_000_000);
        let source_event = CoreEvent::new(
            Timestamp::now(),
            opened_at,
            Origin::from_hostname("test-host"),
            RawData::from_text("401 login attempt"),
        );

        let mut incident = Incident::new(
            "brute_force_campaign",
            "alice",
            Severity::Critical,
            Confidence::new(95),
            sample_message("auth.brute_force_campaign", "Sustained brute force"),
            opened_at,
        )
        .with_techniques(["T1110"])
        .with_context("threat_intel.source", FieldValue::str("AbuseIPDB"));
        incident.add_evidence(&source_event);
        incident.add_evidence(sample_signal("alice", opened_at.add_secs(20)));

        let event = incident.into_event();

        assert_eq!(
            event.get_field("event_type").and_then(|f| f.as_str()),
            Some("incident")
        );
        assert_eq!(
            event
                .get_field("incident.rule_name")
                .and_then(|f| f.as_str()),
            Some("brute_force_campaign")
        );
        assert_eq!(
            event
                .get_field("incident.severity")
                .and_then(|f| f.as_str()),
            Some("critical")
        );
        assert!(matches!(
            event.get_field("incident.evidence"),
            Some(FieldValue::Array(items)) if items.len() == 2
        ));
        assert!(matches!(
            event.get_field("incident.context"),
            Some(FieldValue::Object(_))
        ));
        assert_eq!(
            event.get_field("incident.last_seen"),
            Some(&FieldValue::Time(opened_at.add_secs(20)))
        );
        assert_eq!(event.original_time(), opened_at);
    }

    #[test]
    fn test_evidence_from_conversions() {
        let opened_at = Timestamp::from_secs(1_700_000_000);
        let source_event = CoreEvent::new(
            Timestamp::now(),
            opened_at,
            Origin::from_hostname("test-host"),
            RawData::from_text("401 login attempt"),
        );

        let from_event: Evidence = (&source_event).into();
        assert!(matches!(from_event, Evidence::Event(_)));

        let from_signal: Evidence = sample_signal("alice", opened_at).into();
        assert!(matches!(from_signal, Evidence::Signal(_)));
    }
}
