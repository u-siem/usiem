use std::collections::HashMap;
use std::convert::TryInto;
use usiem::event::field::{FieldConversionError, FieldValue, Ip, Text, Timestamp};

/// Integration tests for field value conversions across different scenarios
#[test]
fn test_real_world_event_parsing() {
    // Simulate parsing a real log entry
    let mut event_fields = HashMap::new();

    // Raw log data as it might come from various sources
    event_fields.insert(
        "timestamp".to_string(),
        FieldValue::Str("2025-10-11T10:30:00Z".into()),
    );
    event_fields.insert(
        "source_ip".to_string(),
        FieldValue::Str("192.168.1.100".into()),
    );
    event_fields.insert(
        "destination_port".to_string(),
        FieldValue::Str("443".into()),
    );
    event_fields.insert(
        "bytes_transferred".to_string(),
        FieldValue::Str("1024".into()),
    );
    event_fields.insert("success".to_string(), FieldValue::Str("true".into()));

    // Test conversions work as expected in real scenarios
    let timestamp: Timestamp = (&event_fields["timestamp"]).try_into().unwrap();
    let source_ip: Ip = (&event_fields["source_ip"]).try_into().unwrap();
    let dest_port: u32 = (&event_fields["destination_port"]).try_into().unwrap();
    let bytes: u64 = (&event_fields["bytes_transferred"]).try_into().unwrap();
    let success: bool = (&event_fields["success"]).try_into().unwrap();

    assert!(timestamp.as_nanos() > 0);
    assert_eq!(source_ip.to_string(), "192.168.1.100");
    assert_eq!(dest_port, 443);
    assert_eq!(bytes, 1024);
    assert_eq!(success, true);
}

#[test]
fn test_mixed_type_array_processing() {
    // Test processing arrays with mixed types (common in JSON logs)
    let mixed_array = vec![
        FieldValue::Int(42),
        FieldValue::Str("hello".into()),
        FieldValue::Float(3.14),
        FieldValue::Bool(true),
    ];

    // Convert all to strings for logging/display
    let string_values: Result<Vec<String>, FieldConversionError> =
        mixed_array.iter().map(|v| v.try_into()).collect();

    let strings = string_values.unwrap();
    assert_eq!(strings, vec!["42", "hello", "3.14", "true"]);
}

#[test]
fn test_nested_object_field_extraction() {
    // Test extracting values from nested objects (common in structured logs)
    let mut inner_obj = HashMap::new();
    inner_obj.insert("user_id".into(), FieldValue::Int(12345));
    inner_obj.insert("session_id".into(), FieldValue::Str("sess_abc123".into()));

    let mut outer_obj = HashMap::new();
    outer_obj.insert("metadata".into(), FieldValue::Object(inner_obj));
    outer_obj.insert("event_type".into(), FieldValue::Str("login".into()));

    let root_field = FieldValue::Object(outer_obj);

    // Extract nested values
    if let FieldValue::Object(ref root) = root_field {
        if let Some(FieldValue::Object(metadata)) = root.get("metadata") {
            let user_id: i64 = (&metadata["user_id"]).try_into().unwrap();
            let session_id: String = (&metadata["session_id"]).try_into().unwrap();

            assert_eq!(user_id, 12345);
            assert_eq!(session_id, "sess_abc123");
        }
    }
}

#[test]
fn test_error_handling_scenarios() {
    // Test various error conditions that might occur in production

    // Invalid IP address
    let invalid_ip = FieldValue::Str("not.an.ip".into());
    let ip_result: Result<Ip, FieldConversionError> = invalid_ip.try_into();
    assert!(matches!(
        ip_result,
        Err(FieldConversionError::InvalidIpAddress(_))
    ));

    // Invalid timestamp
    let invalid_time = FieldValue::Str("not-a-timestamp".into());
    let time_result: Result<Timestamp, FieldConversionError> = invalid_time.try_into();
    assert!(matches!(
        time_result,
        Err(FieldConversionError::InvalidTimeFormat(_))
    ));

    // Number out of range
    let huge_number = FieldValue::Int(i64::MAX);
    let u32_result: Result<u32, FieldConversionError> = huge_number.try_into();
    assert!(matches!(
        u32_result,
        Err(FieldConversionError::OutOfRange { .. })
    ));

    // Incompatible type conversion
    let bytes_field = FieldValue::Bytes(vec![1, 2, 3]);
    let ip_result: Result<Ip, FieldConversionError> = bytes_field.try_into();
    assert!(matches!(
        ip_result,
        Err(FieldConversionError::IncompatibleType { .. })
    ));
}

#[test]
fn test_performance_critical_conversions() {
    // Test conversions that might be done frequently in a SIEM system
    let timestamp_str = FieldValue::Str("2025-10-11T10:30:00.123456789Z".into());

    // High-frequency timestamp parsing
    for _ in 0..1000 {
        let _: Timestamp = timestamp_str.clone().try_into().unwrap();
    }

    // High-frequency IP parsing
    let ip_str = FieldValue::Str("10.0.0.1".into());
    for _ in 0..1000 {
        let _: Ip = ip_str.clone().try_into().unwrap();
    }

    // High-frequency number parsing
    let num_str = FieldValue::Str("12345".into());
    for _ in 0..1000 {
        let _: i64 = num_str.clone().try_into().unwrap();
    }
}

#[test]
fn test_cow_string_performance() {
    // Test that Cow strings provide expected performance benefits
    let static_str: Text = "static_string".into();
    let owned_str: Text = String::from("owned_string").into();

    // Both should work seamlessly
    let field1 = FieldValue::Str(static_str);
    let field2 = FieldValue::Str(owned_str);

    let str1: String = field1.try_into().unwrap();
    let str2: String = field2.try_into().unwrap();

    assert_eq!(str1, "static_string");
    assert_eq!(str2, "owned_string");
}

#[test]
fn test_siem_analytics_with_math_operations() {
    // Simulate SIEM analytics scenarios using mathematical operations

    // Risk scoring calculation
    let base_risk = FieldValue::Int(10);
    let severity_multiplier = FieldValue::Float(2.5);
    let time_factor = FieldValue::Int(3);

    // Calculate risk score: base * severity * time_factor
    let intermediate = (base_risk * severity_multiplier).unwrap();
    let final_risk = (intermediate * time_factor).unwrap();

    if let FieldValue::Float(score) = final_risk {
        assert_eq!(score, 75.0); // 10 * 2.5 * 3 = 75
    }

    // Bandwidth calculation
    let bytes_sent = FieldValue::Uint(1048576); // 1MB
    let duration_seconds = FieldValue::Uint(10);
    let bandwidth_bps = (bytes_sent / duration_seconds).unwrap(); // bytes per second

    if let FieldValue::Uint(bps) = bandwidth_bps {
        assert_eq!(bps, 104857); // 1048576 / 10
    }

    // Event count aggregation
    let failed_logins = FieldValue::Int(5);
    let suspicious_connections = FieldValue::Int(3);
    let malware_detections = FieldValue::Int(1);

    let total_incidents = (failed_logins + suspicious_connections).unwrap();
    let total_incidents = (total_incidents + malware_detections).unwrap();

    assert_eq!(total_incidents, FieldValue::Int(9));

    // Time-based alerting
    let event_time = FieldValue::Time(Timestamp::now());
    let alert_window = FieldValue::Int(300); // 5 minutes

    let alert_deadline = (event_time.clone() + alert_window.clone()).unwrap();

    if let FieldValue::Time(deadline) = alert_deadline {
        if let FieldValue::Time(original_time) = event_time {
            assert!(deadline > original_time);
        }
    }
}

#[test]
fn test_field_comparison_and_filtering() {
    // Simulate filtering operations common in SIEM queries

    let events = vec![
        ("event1", FieldValue::Int(5)),  // Low priority
        ("event2", FieldValue::Int(15)), // Medium priority
        ("event3", FieldValue::Int(25)), // High priority
        ("event4", FieldValue::Int(35)), // Critical priority
    ];

    let priority_threshold = FieldValue::Int(20);

    // Filter high-priority events (>= 20)
    let high_priority_events: Vec<&str> = events
        .iter()
        .filter(|(_, priority)| priority >= &priority_threshold)
        .map(|(name, _)| *name)
        .collect();

    assert_eq!(high_priority_events, vec!["event3", "event4"]);

    // Test timestamp ordering for event correlation
    let now = Timestamp::now();
    let five_min_ago = now.sub_secs(300);
    let ten_min_ago = now.sub_secs(600);

    let mut time_events = vec![
        ("latest", FieldValue::Time(now)),
        ("middle", FieldValue::Time(five_min_ago)),
        ("oldest", FieldValue::Time(ten_min_ago)),
    ];

    // Sort by time (oldest first)
    time_events.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap());

    assert_eq!(time_events[0].0, "oldest");
    assert_eq!(time_events[1].0, "middle");
    assert_eq!(time_events[2].0, "latest");
}

#[test]
fn test_copyable_field_operations_in_siem() {
    // Test copyable field functionality for SIEM operations
    let cpu_usage = FieldValue::Float(75.5);
    let memory_usage = FieldValue::Float(82.3);
    let disk_io = FieldValue::Uint(1024);

    // Perform arithmetic operations directly with FieldValue
    let total_load = (cpu_usage.clone() + memory_usage.clone()).unwrap();
    let load_factor = (cpu_usage.clone() * FieldValue::Float(0.01)).unwrap();
    let io_efficiency = (disk_io.clone() / FieldValue::Float(10.0)).unwrap();

    assert_eq!(total_load, FieldValue::Float(157.8));
    assert_eq!(load_factor, FieldValue::Float(0.755));
    assert_eq!(io_efficiency, FieldValue::Float(102.4));

    // Test that copying works for all copyable types (Copy types: Int, Uint, Float, Bool, Time, Ip)
    let timestamp_field = FieldValue::Time(Timestamp::now());
    let ip_field = FieldValue::Ip(Ip::from_str("192.168.1.1").unwrap());
    let bool_field = FieldValue::Bool(true);
    let int_field = FieldValue::Int(42);
    let uint_field = FieldValue::Uint(100);
    let float_field = FieldValue::Float(3.14);

    // Test is_copyable for copyable types
    assert!(timestamp_field.is_copyable());
    assert!(ip_field.is_copyable());
    assert!(bool_field.is_copyable());
    assert!(int_field.is_copyable());
    assert!(uint_field.is_copyable());
    assert!(float_field.is_copyable());

    // Test copy_if_copyable for copyable types
    assert_eq!(timestamp_field.copy_if_copyable().unwrap(), timestamp_field);
    assert_eq!(ip_field.copy_if_copyable().unwrap(), ip_field);
    assert_eq!(bool_field.copy_if_copyable().unwrap(), bool_field);
    assert_eq!(int_field.copy_if_copyable().unwrap(), int_field);
    assert_eq!(uint_field.copy_if_copyable().unwrap(), uint_field);
    assert_eq!(float_field.copy_if_copyable().unwrap(), float_field);

    // Test non-copyable types (contain non-Copy data: Str, Bytes, Object, Array)
    let string_field = FieldValue::Str("test".into());
    let bytes_field = FieldValue::Bytes(vec![1, 2, 3]);

    assert!(!string_field.is_copyable());
    assert!(!bytes_field.is_copyable());
    assert_eq!(string_field.copy_if_copyable(), None);
    assert_eq!(bytes_field.copy_if_copyable(), None);

    // Demonstrate the benefit: copyable fields can be used without cloning when you need the values multiple times
    let sensor_value = FieldValue::Float(98.6);
    if sensor_value.is_copyable() {
        // We can safely use copy_if_copyable multiple times without expensive clones
        let alert_threshold = sensor_value.copy_if_copyable().unwrap();
        let log_value = sensor_value.copy_if_copyable().unwrap();
        let archive_value = sensor_value.copy_if_copyable().unwrap();

        assert_eq!(alert_threshold, FieldValue::Float(98.6));
        assert_eq!(log_value, FieldValue::Float(98.6));
        assert_eq!(archive_value, FieldValue::Float(98.6));
    }
}
