//! Well-known field names, following the
//! [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
//! (ECS) wherever ECS has a name for the concept.
//!
//! Parsers, enrichment, query front-ends and rule engines that agree on these
//! names can interoperate without per-source field mappings. Using them is
//! optional: `Event` fields are plain strings, and nothing in this crate
//! rejects a name that isn't listed here.
//!
//! The `ARTIFACT_*` names are not ECS. They mirror forensic-rs
//! (`forensic_rs::dictionary`) so forensic artifacts keep their provenance
//! when converted to events.
//!
//! ```
//! use usiem::event::fields;
//! use usiem::event::{Event, FieldValue, Origin, RawData};
//!
//! let mut event = Event::new(
//!     0.into(),
//!     0.into(),
//!     Origin::Collector("demo".into()),
//!     RawData::from_text(""),
//! );
//! event.add_field(fields::USER_NAME, FieldValue::from("alice"));
//! assert!(event.get_field(fields::USER_NAME).is_some());
//! ```

// --- event ---
/// The event's [`crate::event::EventId`] in 16-hex-digit form, written
/// when the event is stored so later links (alerts, evidence) can name it.
pub const EVENT_ID: &str = "event.id";
/// Outcome of the event: `success`, `failure` or `unknown`.
pub const EVENT_OUTCOME: &str = "event.outcome";
/// The action captured by the event, e.g. `user-login`, `process-started`.
pub const EVENT_ACTION: &str = "event.action";
/// ECS "big bucket": authentication, file, process, network, registry, ...
pub const EVENT_CATEGORY: &str = "event.category";
/// Source-specific event code, e.g. the Windows Event ID.
pub const EVENT_CODE: &str = "event.code";
/// Name of the dataset the event belongs to, e.g. `windows.security`.
pub const EVENT_DATASET: &str = "event.dataset";
/// Name of the module/product that produced the event.
pub const EVENT_PROVIDER: &str = "event.provider";
/// Why the event happened, e.g. the reason a request was refused.
pub const EVENT_REASON: &str = "event.reason";
/// Free-form human readable message.
pub const MESSAGE: &str = "message";
/// Original log severity text, e.g. `Information`, `ERROR`.
pub const LOG_LEVEL: &str = "log.level";

// --- host ---
pub const HOST_NAME: &str = "host.name";
pub const HOST_IP: &str = "host.ip";
pub const HOST_OS_NAME: &str = "host.os.name";
pub const HOST_OS_VERSION: &str = "host.os.version";

// --- user ---
pub const USER_NAME: &str = "user.name";
pub const USER_DOMAIN: &str = "user.domain";
/// Unique user identifier; the SID on Windows.
pub const USER_ID: &str = "user.id";
pub const USER_TARGET_NAME: &str = "user.target.name";
pub const USER_TARGET_DOMAIN: &str = "user.target.domain";
pub const USER_TARGET_ID: &str = "user.target.id";
/// Not ECS: `true` when the system says the account does not exist (e.g.
/// sshd's "invalid user").
pub const USER_INVALID: &str = "user.invalid";

// --- ssh (not ECS) ---
/// Authentication method of an SSH login: `password`, `publickey`, ...
pub const SSH_METHOD: &str = "ssh.method";

// --- network ---
pub const SOURCE_IP: &str = "source.ip";
pub const SOURCE_PORT: &str = "source.port";
pub const SOURCE_DOMAIN: &str = "source.domain";
/// Same form as [`CLIENT_MAC`].
pub const SOURCE_MAC: &str = "source.mac";
/// Bytes sent by the source.
pub const SOURCE_BYTES: &str = "source.bytes";
pub const DESTINATION_IP: &str = "destination.ip";
pub const DESTINATION_PORT: &str = "destination.port";
pub const DESTINATION_DOMAIN: &str = "destination.domain";
/// Same form as [`CLIENT_MAC`].
pub const DESTINATION_MAC: &str = "destination.mac";
/// Bytes sent by the destination.
pub const DESTINATION_BYTES: &str = "destination.bytes";
pub const CLIENT_IP: &str = "client.ip";
/// MAC address, upper-case hex pairs joined by `-` as ECS asks (`AA-BB-CC-DD-EE-FF`).
pub const CLIENT_MAC: &str = "client.mac";
/// The client's own name, e.g. the hostname it sent with a DHCP request.
pub const CLIENT_DOMAIN: &str = "client.domain";
pub const NETWORK_TRANSPORT: &str = "network.transport";
pub const NETWORK_PROTOCOL: &str = "network.protocol";
pub const NETWORK_DURATION: &str = "network.duration";
/// `ingress` or `egress`, relative to the observer's interface.
pub const NETWORK_DIRECTION: &str = "network.direction";
pub const OBSERVER_IP: &str = "observer.ip";
pub const OBSERVER_NAME: &str = "observer.name";
pub const OBSERVER_INGRESS_INTERFACE: &str = "observer.ingress.interface";
pub const OBSERVER_EGRESS_INTERFACE: &str = "observer.egress.interface";

// --- geo / autonomous system (written by GeoIP enrichment) ---
pub const SOURCE_GEO_COUNTRY_ISO_CODE: &str = "source.geo.country_iso_code";
pub const SOURCE_GEO_COUNTRY_NAME: &str = "source.geo.country_name";
pub const SOURCE_GEO_CITY_NAME: &str = "source.geo.city_name";
pub const SOURCE_GEO_LOCATION_LAT: &str = "source.geo.location.lat";
pub const SOURCE_GEO_LOCATION_LON: &str = "source.geo.location.lon";
/// Autonomous system number of the source address.
pub const SOURCE_AS_NUMBER: &str = "source.as.number";
pub const SOURCE_AS_ORGANIZATION_NAME: &str = "source.as.organization.name";
pub const DESTINATION_GEO_COUNTRY_ISO_CODE: &str = "destination.geo.country_iso_code";
pub const DESTINATION_GEO_COUNTRY_NAME: &str = "destination.geo.country_name";
pub const DESTINATION_GEO_CITY_NAME: &str = "destination.geo.city_name";
pub const DESTINATION_GEO_LOCATION_LAT: &str = "destination.geo.location.lat";
pub const DESTINATION_GEO_LOCATION_LON: &str = "destination.geo.location.lon";
/// Autonomous system number of the destination address.
pub const DESTINATION_AS_NUMBER: &str = "destination.as.number";
pub const DESTINATION_AS_ORGANIZATION_NAME: &str = "destination.as.organization.name";

// --- web ---
pub const URL_FULL: &str = "url.full";
pub const URL_DOMAIN: &str = "url.domain";
pub const URL_PATH: &str = "url.path";
pub const URL_QUERY: &str = "url.query";
pub const HTTP_REQUEST_METHOD: &str = "http.request.method";
pub const HTTP_RESPONSE_MIME_TYPE: &str = "http.response.mime_type";
pub const HTTP_RESPONSE_STATUS_CODE: &str = "http.response.status_code";
pub const USER_AGENT_ORIGINAL: &str = "user_agent.original";

// --- dns / dhcp ---
pub const DNS_OP_CODE: &str = "dns.op_code";
pub const DNS_QUESTION_NAME: &str = "dns.question.name";
pub const DNS_QUESTION_TYPE: &str = "dns.question.type";
pub const DNS_QUESTION_CLASS: &str = "dns.question.class";
pub const DNS_ANSWER_NAME: &str = "dns.answer.name";
pub const DNS_ANSWER_TYPE: &str = "dns.answer.type";
pub const DNS_ANSWER_CLASS: &str = "dns.answer.class";
pub const DNS_ANSWER_TTL: &str = "dns.answer.ttl";
pub const DNS_ANSWER_DATA: &str = "dns.answer.data";
pub const DNS_RESOLVED_IP: &str = "dns.resolved_ip";
/// `NXDOMAIN`, `NODATA`, `SERVFAIL`, ...
pub const DNS_RESPONSE_CODE: &str = "dns.response_code";
pub const DHCP_TYPE: &str = "dhcp.type";

// --- process ---
pub const PROCESS_PID: &str = "process.pid";
pub const PROCESS_NAME: &str = "process.name";
pub const PROCESS_EXECUTABLE: &str = "process.executable";
pub const PROCESS_COMMAND_LINE: &str = "process.command_line";
pub const PROCESS_WORKING_DIRECTORY: &str = "process.working_directory";
pub const PROCESS_PARENT_PID: &str = "process.parent.pid";
pub const PROCESS_PARENT_NAME: &str = "process.parent.name";
pub const PROCESS_PARENT_EXECUTABLE: &str = "process.parent.executable";
pub const PROCESS_PARENT_COMMAND_LINE: &str = "process.parent.command_line";

// --- file ---
pub const FILE_NAME: &str = "file.name";
pub const FILE_PATH: &str = "file.path";
pub const FILE_DIRECTORY: &str = "file.directory";
pub const FILE_EXTENSION: &str = "file.extension";
pub const FILE_SIZE: &str = "file.size";
pub const FILE_TYPE: &str = "file.type";
pub const FILE_INODE: &str = "file.inode";
pub const FILE_DEVICE: &str = "file.device";
pub const FILE_OWNER: &str = "file.owner";
pub const FILE_CREATED: &str = "file.created";
pub const FILE_ACCESSED: &str = "file.accessed";
pub const FILE_MTIME: &str = "file.mtime";
pub const FILE_HASH_MD5: &str = "file.hash.md5";
pub const FILE_HASH_SHA1: &str = "file.hash.sha1";
pub const FILE_HASH_SHA256: &str = "file.hash.sha256";
pub const PE_IMPORTS: &str = "pe.imports";

// --- registry ---
pub const REGISTRY_HIVE: &str = "registry.hive";
pub const REGISTRY_KEY: &str = "registry.key";
pub const REGISTRY_PATH: &str = "registry.path";
pub const REGISTRY_VALUE: &str = "registry.value";
pub const REGISTRY_DATA_STRINGS: &str = "registry.data.strings";

// --- rule (detections) ---
pub const RULE_NAME: &str = "rule.name";
pub const RULE_ID: &str = "rule.id";
pub const RULE_CATEGORY: &str = "rule.category";
pub const RULE_UUID: &str = "rule.uuid";

// --- group ---
pub const GROUP_NAME: &str = "group.name";
pub const GROUP_ID: &str = "group.id";

// --- threat intel (written when an event matches an indicator feed) ---
/// The listed IP the event matched.
pub const THREAT_INDICATOR_IP: &str = "threat.indicator.ip";
/// The listed domain the event matched (the listed suffix, not the full name).
pub const THREAT_INDICATOR_DOMAIN: &str = "threat.indicator.domain";
/// `ipv4-addr`, `ipv6-addr` or `domain-name` (STIX names, as ECS uses).
pub const THREAT_INDICATOR_TYPE: &str = "threat.indicator.type";
/// The event field that held the indicator, e.g. `destination.ip`.
pub const THREAT_INDICATOR_MATCHED_FIELD: &str = "threat.indicator.matched.field";
/// The feed(s) listing the indicator.
pub const THREAT_FEED_NAME: &str = "threat.feed.name";
/// MITRE ATT&CK technique ids, e.g. `T1110.001`.
pub const THREAT_TECHNIQUE_ID: &str = "threat.technique.id";
/// MITRE ATT&CK technique names, in the order of [`THREAT_TECHNIQUE_ID`].
pub const THREAT_TECHNIQUE_NAME: &str = "threat.technique.name";
/// MITRE ATT&CK tactic ids, e.g. `TA0006`.
pub const THREAT_TACTIC_ID: &str = "threat.tactic.id";
/// MITRE ATT&CK tactic names, e.g. `Credential Access`.
pub const THREAT_TACTIC_NAME: &str = "threat.tactic.name";

// --- risk (risk-based alerting) ---
/// Risk points one finding adds to an entity.
pub const RISK_SCORE: &str = "risk.score";
/// The entity's kind: `host`, `user`, `ip`, `device`, ... (see
/// `processing::entity::EntityKind`).
pub const RISK_ENTITY_TYPE: &str = "risk.entity.type";
/// The entity's normalised id.
pub const RISK_ENTITY_ID: &str = "risk.entity.id";

// --- alerts ---
pub const ALERT_ID: &str = "alert.id";
/// A risk alert's total: the points its entity collected in the window.
pub const ALERT_RISK_SCORE: &str = "alert.risk_score";
/// What raised it, e.g. `intel:feodo`.
pub const ALERT_RULE: &str = "alert.rule";
pub const ALERT_SEVERITY: &str = "alert.severity";

// --- windows event log ---
pub const WINLOG_CHANNEL: &str = "winlog.channel";
pub const WINLOG_EVENT_ID: &str = "winlog.event_id";
pub const WINLOG_RECORD_ID: &str = "winlog.record_id";
pub const WINLOG_PROVIDER_NAME: &str = "winlog.provider_name";
pub const WINLOG_COMPUTER_NAME: &str = "winlog.computer_name";
pub const WINLOG_LOGON_TYPE: &str = "winlog.logon.type";
/// Prefix for the raw `EventData` members, e.g. `winlog.event_data.TargetUserName`.
pub const WINLOG_EVENT_DATA_PREFIX: &str = "winlog.event_data.";

// --- forensic artifacts (forensic-rs provenance, not ECS) ---
/// Artifact type as a `::` path, e.g. `Windows::WinEvt::Security`.
pub const ARTIFACT_NAME: &str = "artifact.name";
/// Path of the file the artifact was parsed from.
pub const ARTIFACT_PATH: &str = "artifact.path";
/// Host the artifact was collected from.
pub const ARTIFACT_HOST: &str = "artifact.host";
pub const ARTIFACT_TENANT: &str = "artifact.tenant";
/// Which timestamp of the artifact `original_time` represents:
/// `creation`, `modification`, `accessed` or a free-form name.
pub const TIMELINE_CONTEXT: &str = "timeline.context";
