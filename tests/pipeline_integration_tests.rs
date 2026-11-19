//! End-to-end tests wiring the parser registry into a processing `Pipeline`.
//!
//! Prior to this, parsing (`ingest::parser`) and processing (`processing::pipeline`)
//! had never been exercised together anywhere in the test suite — each subsystem
//! was only ever tested in isolation.

use usiem::event::CoreEvent as Event;
use usiem::event::field::FieldValue;
use usiem::prelude::{ParseResult, ParserRegistry, RawEvent, apache_common_parser};
use usiem::processing::pipeline::{Pipeline, ProcessResult, Processor};

fn tag_client_ip_as_internal(mut event: Event) -> ProcessResult {
    let is_internal = event
        .get_field("client.ip")
        .and_then(|f| f.as_str())
        .map(|ip| ip.starts_with("10.") || ip.starts_with("192.168."))
        .unwrap_or(false);
    event.add_field("client.ip.is_internal", FieldValue::Bool(is_internal));
    ProcessResult::Continue(event)
}

#[test]
fn test_parsed_apache_event_flows_through_pipeline() {
    let mut registry = ParserRegistry::new();
    registry.register(apache_common_parser());

    let log =
        r#"192.168.1.50 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 2326"#;
    let raw = RawEvent::from_log(log, "access.log");

    let parsed_event = match registry.parse(raw) {
        ParseResult::Success(event) => event,
        other => panic!("expected the Apache parser to match, got {other:?}"),
    };

    // The parser should have recovered the log's own timestamp, not ingest time.
    assert_eq!(
        parsed_event.original_time().to_rfc3339(),
        "2023-12-25T10:00:00Z"
    );

    let mut pipeline = Pipeline::new();
    pipeline.add_stage(Processor::new(
        "tag_internal_ip",
        "Flags client IPs from private ranges",
        tag_client_ip_as_internal,
    ));

    match pipeline.run(parsed_event) {
        ProcessResult::Continue(event) => {
            assert_eq!(
                event.get_field("client.ip.is_internal"),
                Some(&FieldValue::Bool(true))
            );
            assert_eq!(
                event.get_field("event_type").and_then(|f| f.as_str()),
                Some("web_access")
            );
        }
        other => panic!("expected the event to continue through the pipeline, got {other:?}"),
    }

    let stage = pipeline.metadata().get_stage("tag_internal_ip").unwrap();
    assert!(stage.exit_time.is_some());
}

#[test]
fn test_unparsed_log_never_reaches_pipeline() {
    let mut registry = ParserRegistry::new();
    registry.register(apache_common_parser());

    let raw = RawEvent::from_log("not an apache log line", "access.log");
    match registry.parse(raw) {
        ParseResult::NoMatch(_) => {}
        other => panic!("expected NoMatch for an unrecognized log line, got {other:?}"),
    }
}
