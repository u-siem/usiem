use usiem::event::ObjectBuilder;
use usiem::event::field::FieldValue;

#[test]
fn test_string_contains() {
    let field = FieldValue::str("Hello World Security Event");

    // Case sensitive contains
    assert!(field.contains("World"));
    assert!(field.contains("Security"));
    assert!(field.contains("Hello"));
    assert!(!field.contains("world")); // Case sensitive
    assert!(!field.contains("SECURITY"));

    // Case insensitive contains
    assert!(field.contains_ignore_case("world"));
    assert!(field.contains_ignore_case("SECURITY"));
    assert!(field.contains_ignore_case("hELLo"));
    assert!(!field.contains_ignore_case("xyz"));
}

#[test]
fn test_string_starts_with_ends_with() {
    let field = FieldValue::str("SecurityEvent.Authentication.Failed");

    // Case sensitive
    assert!(field.starts_with("Security"));
    assert!(field.ends_with("Failed"));
    assert!(!field.starts_with("security")); // Case sensitive
    assert!(!field.ends_with("failed"));

    // Case insensitive
    assert!(field.starts_with_ignore_case("security"));
    assert!(field.starts_with_ignore_case("SECURITY"));
    assert!(field.ends_with_ignore_case("failed"));
    assert!(field.ends_with_ignore_case("FAILED"));
}

#[test]
fn test_string_equals() {
    let field = FieldValue::str("admin");

    // Case sensitive
    assert!(field.equals("admin"));
    assert!(!field.equals("Admin"));
    assert!(!field.equals("ADMIN"));

    // Case insensitive
    assert!(field.equals_ignore_case("admin"));
    assert!(field.equals_ignore_case("Admin"));
    assert!(field.equals_ignore_case("ADMIN"));
    assert!(field.equals_ignore_case("aDmIn"));
}

#[test]
fn test_string_length_and_empty() {
    let empty_field = FieldValue::str("");
    let field = FieldValue::str("test");
    let long_field = FieldValue::str("This is a longer security event message");

    assert_eq!(empty_field.len(), 0);
    assert!(empty_field.is_empty());

    assert_eq!(field.len(), 4);
    assert!(!field.is_empty());

    assert_eq!(long_field.len(), 39);
    assert!(!long_field.is_empty());
}

#[test]
fn test_string_case_conversion() {
    let field = FieldValue::str("Security Event Alert");

    assert_eq!(field.to_lowercase(), "security event alert");
    assert_eq!(field.to_uppercase(), "SECURITY EVENT ALERT");
}

#[test]
fn test_string_trim() {
    let field = FieldValue::str("  \t\n  Security Event  \t\n  ");

    assert_eq!(field.trim(), "Security Event");

    let no_whitespace = FieldValue::str("NoWhitespace");
    assert_eq!(no_whitespace.trim(), "NoWhitespace");
}

#[test]
fn test_string_split() {
    let field = FieldValue::str("user.login.success");

    let parts = field.split(".");
    assert_eq!(parts, vec!["user", "login", "success"]);

    let csv_field = FieldValue::str("192.168.1.1,admin,login,success");
    let csv_parts = field.split(",");
    assert_eq!(csv_parts.len(), 1); // Original field doesn't contain commas

    let csv_parts = csv_field.split(",");
    assert_eq!(csv_parts, vec!["192.168.1.1", "admin", "login", "success"]);
}

#[test]
fn test_string_pattern_matching() {
    let field = FieldValue::str("Failed login attempt from 192.168.1.100");

    assert!(field.matches_pattern("Failed"));
    assert!(field.matches_pattern("192.168"));
    assert!(field.matches_pattern("login"));
    assert!(!field.matches_pattern("success"));
}

#[test]
fn test_non_string_field_behavior() {
    let int_field = FieldValue::int(42);
    let bool_field = FieldValue::bool(true);
    let float_field = FieldValue::float(4.25);

    // All string operations should return false/empty for non-string fields
    assert!(!int_field.contains("42"));
    assert!(!bool_field.starts_with("true"));
    assert!(!float_field.ends_with("25"));
    assert!(!int_field.equals("42"));

    assert_eq!(int_field.len(), 0);
    assert!(bool_field.is_empty());
    assert_eq!(float_field.to_lowercase(), "");
    assert_eq!(int_field.to_uppercase(), "");
    assert_eq!(bool_field.trim(), "");
    assert_eq!(float_field.split("."), Vec::<String>::new());
}

#[test]
fn test_fluent_string_operations() {
    let event = ObjectBuilder::new()
        .str("event_type", "Authentication")
        .str("username", "  admin  ")
        .str("source_ip", "192.168.1.100")
        .str("message", "Login attempt failed for user")
        .str("empty_field", "")
        .build();

    // Test fluent access with string utilities
    assert!(event.get("event_type").contains("Auth"));
    assert!(event.get("event_type").contains_ignore_case("auth"));
    assert!(event.get("event_type").starts_with("Auth"));
    assert!(event.get("event_type").equals_ignore_case("authentication"));

    assert_eq!(event.get("username").len(), 9); // "  admin  " = 9 chars (2+5+2)
    assert_eq!(event.get("username").trim(), "admin");

    assert!(event.get("source_ip").starts_with("192.168"));
    assert!(event.get("source_ip").contains(".100"));

    assert!(event.get("message").contains("failed"));
    assert!(event.get("message").contains_ignore_case("LOGIN"));

    assert!(event.get("empty_field").is_empty());
    assert_eq!(event.get("empty_field").len(), 0);

    // Test missing field behavior
    assert!(!event.get("missing_field").contains("anything"));
    assert!(event.get("missing_field").is_empty());
    assert_eq!(event.get("missing_field").len(), 0);
}

#[test]
fn test_real_world_siem_scenarios() {
    let security_event = ObjectBuilder::new()
        .str("event_type", "security.authentication.failed")
        .str("username", "admin@company.com")
        .str("source_ip", "192.168.1.100")
        .str("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .str("error_message", "Invalid credentials provided")
        .str("url", "/admin/login")
        .build();

    // Event type classification
    assert!(security_event.get("event_type").starts_with("security"));
    assert!(security_event.get("event_type").contains("authentication"));
    assert!(security_event.get("event_type").ends_with("failed"));

    // Email validation
    assert!(security_event.get("username").contains("@"));
    assert!(security_event.get("username").ends_with(".com"));

    // IP analysis
    assert!(security_event.get("source_ip").starts_with("192.168"));

    // User agent analysis
    assert!(security_event.get("user_agent").contains("Windows"));
    assert!(
        security_event
            .get("user_agent")
            .contains_ignore_case("mozilla")
    );

    // Error classification
    assert!(
        security_event
            .get("error_message")
            .contains_ignore_case("invalid")
    );
    assert!(
        security_event
            .get("error_message")
            .contains_ignore_case("credentials")
    );

    // URL analysis
    assert!(security_event.get("url").starts_with("/"));
    assert!(security_event.get("url").contains("admin"));
}

#[test]
fn test_case_insensitive_threat_detection() {
    let events = [
        ObjectBuilder::new()
            .str("command", "powershell.exe -ExecutionPolicy Bypass")
            .build(),
        ObjectBuilder::new()
            .str("command", "POWERSHELL.EXE -ENCODED")
            .build(),
        ObjectBuilder::new()
            .str("command", "PowerShell -NoProfile -WindowStyle Hidden")
            .build(),
        ObjectBuilder::new().str("filename", "mimikatz.exe").build(),
        ObjectBuilder::new().str("filename", "MIMIKATZ.EXE").build(),
        ObjectBuilder::new()
            .str("process", "cmd.exe /c whoami")
            .build(),
    ];

    // Detect PowerShell usage (case insensitive)
    let powershell_events: Vec<_> = events
        .iter()
        .filter(|event| event.get("command").contains_ignore_case("powershell"))
        .collect();
    assert_eq!(powershell_events.len(), 3);

    // Detect specific tools
    let mimikatz_events: Vec<_> = events
        .iter()
        .filter(|event| event.get("filename").equals_ignore_case("mimikatz.exe"))
        .collect();
    assert_eq!(mimikatz_events.len(), 2);

    // Command injection patterns
    let injection_events: Vec<_> = events
        .iter()
        .filter(|event| {
            event.get("command").contains("cmd.exe") || event.get("process").contains("cmd.exe")
        })
        .collect();
    assert_eq!(injection_events.len(), 1);
}
