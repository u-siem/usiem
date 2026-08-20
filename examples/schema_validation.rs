//! Demonstrates checking parsed events against a [`Schema`], two ways:
//! [`Schema::validate`] reports what's wrong without touching the event,
//! while [`Schema::conform`] mutates it, removing whatever doesn't conform.
//! Neither can be wired into a `Pipeline` as a `Processor` stage — those are
//! bare `fn` pointers with no room to close over a loaded `Schema` — so both
//! are called directly here, the same way you'd call your own
//! correlation/detection logic after parsing.
//!
//! Run with: `cargo run --example schema_validation --features json`

use usiem::prelude::*;

/// The shape a "web_access" event is expected to have.
fn web_access_schema() -> Schema {
    let mut schema = Schema::new("web_access", "1.0");
    schema.add_field("event_type", Schema::str_field().required().build());
    schema.add_field("client.ip", Schema::str_field().required().build());
    schema.add_field(
        "http.response.status_code",
        Schema::int_field()
            .required()
            .min_value(100.0)
            .max_value(599.0)
            .build(),
    );
    schema
}

/// A schema with a nested `user` object, to show `validate` recursing into
/// `FieldValue::Object` rather than treating it as an opaque blob.
#[cfg(feature = "json")]
fn user_event_schema() -> Schema {
    let mut user_schema = Schema::new("user", "1.0");
    user_schema.add_field("id", Schema::int_field().required().build());
    user_schema.add_field("name", Schema::str_field().required().build());

    let mut schema = Schema::new("user_event", "1.0");
    schema.add_field("event_type", Schema::str_field().required().build());
    schema.add_field("user", Schema::object_field(user_schema).required().build());
    schema
}

fn report(label: &str, result: Result<(), Vec<SchemaError>>) {
    match result {
        Ok(()) => println!("[{label}] OK"),
        Err(errors) => {
            println!("[{label}] {} violation(s):", errors.len());
            for e in &errors {
                println!("  - {e}");
            }
        }
    }
}

fn main() {
    let schema = web_access_schema();
    let mut registry = ParserRegistry::new();
    registry.register(apache_common_parser());

    let good_log =
        r#"127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 2326"#;
    if let ParseResult::Success(event) = registry.parse(RawEvent::from_log(good_log, "access.log"))
    {
        report("valid apache log", schema.validate(&event));
    }

    // Same schema, a log with a status code outside the declared range.
    let bad_log =
        r#"127.0.0.1 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 999 2326"#;
    if let ParseResult::Success(event) = registry.parse(RawEvent::from_log(bad_log, "access.log")) {
        report("out-of-range status code", schema.validate(&event));
    }

    // conform mutates in place instead of just reporting: the same
    // out-of-range status code gets removed rather than merely flagged.
    // Nothing is ever added — a schema field with no value present stays
    // absent, even one with a `default_value` (see conform's doc comment).
    if let ParseResult::Success(mut event) =
        registry.parse(RawEvent::from_log(bad_log, "access.log"))
    {
        let removed = schema.conform(&mut event);
        println!(
            "[conform out-of-range status code] removed {} field(s); status_code is now: {:?}",
            removed.len(),
            event.get_field("http.response.status_code")
        );
    }

    // Nested objects: parse real JSON (see ingest::parser::common_parsers's
    // json feature) and validate the resulting FieldValue::Object against a
    // nested sub-schema.
    #[cfg(feature = "json")]
    {
        let user_schema = user_event_schema();
        let mut json_registry = ParserRegistry::new();
        json_registry.register(json_parser());

        let good_json = r#"{"event_type": "user_login", "user": {"id": 42, "name": "alice"}}"#;
        if let ParseResult::Success(event) =
            json_registry.parse(RawEvent::from_log(good_json, "app.log"))
        {
            report("valid nested user event", user_schema.validate(&event));
        }

        // Missing the nested "name" field, and "id" is the wrong type —
        // validate collects both rather than stopping at the first.
        let bad_json = r#"{"event_type": "user_login", "user": {"id": "not-a-number"}}"#;
        if let ParseResult::Success(event) =
            json_registry.parse(RawEvent::from_log(bad_json, "app.log"))
        {
            report("malformed nested user event", user_schema.validate(&event));
        }
    }
    #[cfg(not(feature = "json"))]
    println!("[nested user event] skipped — run with --features json to see this case");
}
