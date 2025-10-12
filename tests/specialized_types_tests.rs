use usiem::event::ObjectBuilder;
use usiem::event::field::FieldValue;

#[test]
fn test_email_extraction() {
    let field = FieldValue::str("admin@example.com");

    let email = field.as_email().expect("Should parse valid email");
    assert_eq!(email.as_str(), "admin@example.com");
    assert_eq!(email.local(), "admin");
    assert_eq!(email.domain(), "example.com");

    // Test domain extraction from email
    let domain = email.domain_parsed();
    assert_eq!(domain.as_str(), "example.com");
    assert_eq!(domain.tld(), "com");
    assert_eq!(domain.sld().unwrap(), "example");

    // Test domain checks
    assert!(email.is_from_domain("example.com"));
    assert!(email.ends_with_domain("example.com"));
    assert!(email.ends_with_domain(".com"));
    assert!(!email.is_from_domain("google.com"));
}

#[test]
fn test_email_validation() {
    // Valid emails
    assert!(FieldValue::str("user@domain.com").as_email().is_ok());
    assert!(FieldValue::str("  test@example.org  ").as_email().is_ok()); // Trimmed

    // Invalid emails
    assert!(FieldValue::str("@domain.com").as_email().is_err()); // No local part
    assert!(FieldValue::str("user@").as_email().is_err()); // No domain
    assert!(FieldValue::str("user@domain").as_email().is_err()); // No TLD
    assert!(FieldValue::str("userdomaincom").as_email().is_err()); // No @
    assert!(FieldValue::str("").as_email().is_err()); // Empty

    // Non-string field
    assert!(FieldValue::int(42).as_email().is_err());
}

#[test]
fn test_domain_extraction() {
    let field = FieldValue::str("subdomain.example.com");

    let domain = field.as_domain().expect("Should parse valid domain");
    assert_eq!(domain.as_str(), "subdomain.example.com");
    assert_eq!(domain.tld(), "com");
    assert_eq!(domain.sld().unwrap(), "example");
    assert_eq!(domain.subdomains(), vec!["subdomain"]);
    assert!(domain.has_subdomains());
    assert!(domain.is_subdomain_of("example.com"));

    // Simple domain
    let simple_field = FieldValue::str("google.com");
    let simple = simple_field
        .as_domain()
        .expect("Should parse simple domain");
    assert_eq!(simple.tld(), "com");
    assert_eq!(simple.sld().unwrap(), "google");
    assert!(simple.subdomains().is_empty());
    assert!(!simple.has_subdomains());
}

#[test]
fn test_domain_validation() {
    // Valid domains
    assert!(FieldValue::str("example.com").as_domain().is_ok());
    assert!(FieldValue::str("sub.example.com").as_domain().is_ok());
    assert!(FieldValue::str("  github.com  ").as_domain().is_ok()); // Trimmed

    // Invalid domains
    assert!(FieldValue::str("").as_domain().is_err()); // Empty
    assert!(FieldValue::str("example").as_domain().is_err()); // No TLD
    assert!(FieldValue::str(".com").as_domain().is_err()); // Empty part
    assert!(FieldValue::str("example.").as_domain().is_err()); // Empty TLD

    // Non-string field
    assert!(FieldValue::bool(true).as_domain().is_err());
}

#[test]
fn test_url_extraction() {
    let field = FieldValue::str("https://www.example.com/path/to/resource?param=value");

    let url = field.as_url().expect("Should parse valid URL");
    assert_eq!(
        url.as_str(),
        "https://www.example.com/path/to/resource?param=value"
    );
    assert_eq!(url.scheme().unwrap(), "https");
    assert_eq!(url.host().unwrap(), "www.example.com");
    assert_eq!(url.path().unwrap(), "/path/to/resource");
    assert_eq!(url.query().unwrap(), "param=value");
    assert!(url.is_https());
    assert!(!url.is_http());

    // Extract domain from URL
    let host_domain = url.host_domain().expect("Should have host domain");
    assert_eq!(host_domain.as_str(), "www.example.com");
    assert_eq!(host_domain.sld().unwrap(), "example");
    assert_eq!(host_domain.tld(), "com");
}

#[test]
fn test_url_variations() {
    // HTTP URL
    let http_field = FieldValue::str("http://example.com");
    let http_url = http_field.as_url().unwrap();
    assert!(http_url.is_http());
    assert!(!http_url.is_https());

    // URL without scheme
    let no_scheme_field = FieldValue::str("example.com/path");
    let no_scheme = no_scheme_field.as_url().unwrap();
    assert_eq!(no_scheme.scheme(), None);
    assert_eq!(no_scheme.host().unwrap(), "example.com");
    assert_eq!(no_scheme.path().unwrap(), "/path");

    // Simple domain
    let simple_field = FieldValue::str("example.com");
    let simple = simple_field.as_url().unwrap();
    assert_eq!(simple.host().unwrap(), "example.com");
    assert_eq!(simple.path(), None);
    assert_eq!(simple.query(), None);
}

#[test]
fn test_specialized_extraction_from_object() {
    let event = ObjectBuilder::new()
        .str("user_email", "security@company.com")
        .str("source_domain", "malicious.example.com")
        .str("redirect_url", "https://phishing.site/login?target=bank")
        .str("invalid_email", "not-an-email")
        .build();

    // Test that the fields exist and have correct string values
    assert_eq!(
        event.get("user_email").as_str().unwrap(),
        "security@company.com"
    );
    assert_eq!(
        event.get("source_domain").as_str().unwrap(),
        "malicious.example.com"
    );
    assert_eq!(
        event.get("redirect_url").as_str().unwrap(),
        "https://phishing.site/login?target=bank"
    );

    // Test failed extraction on invalid data
    assert!(event.get("invalid_email").as_email().is_err());
    assert!(event.get("missing_field").as_email().is_err());

    // Test direct FieldValue extraction
    let email_field = FieldValue::str("security@company.com");
    let email = email_field.as_email().expect("Should extract email");
    assert_eq!(email.local(), "security");
    assert_eq!(email.domain(), "company.com");

    let domain_field = FieldValue::str("malicious.example.com");
    let domain = domain_field.as_domain().expect("Should extract domain");
    assert_eq!(domain.sld().unwrap(), "example");
    assert_eq!(domain.subdomains(), vec!["malicious"]);

    let url_field = FieldValue::str("https://phishing.site/login?target=bank");
    let url = url_field.as_url().expect("Should extract URL");
    assert!(url.is_https());
    assert_eq!(url.host().unwrap(), "phishing.site");
}

#[test]
fn test_siem_security_analysis() {
    // Test direct field value analysis
    let user_email_field = FieldValue::str("admin@internal.company.com");
    let user_email = user_email_field.as_email().unwrap();
    assert!(user_email.ends_with_domain("company.com"));
    assert!(!user_email.ends_with_domain("gmail.com"));

    let user_domain = user_email.domain_parsed();
    assert!(user_domain.has_subdomains());
    assert_eq!(user_domain.subdomains(), vec!["internal"]);

    // Threat domain analysis
    let threat_domain_field = FieldValue::str("suspicious.attacker.evil");
    let threat_domain = threat_domain_field.as_domain().unwrap();
    assert_eq!(threat_domain.tld(), "evil");
    assert!(threat_domain.is_subdomain_of("attacker.evil"));

    // Phishing URL analysis
    let phish_url_field = FieldValue::str("http://fake-bank.com/login");
    let phish_url = phish_url_field.as_url().unwrap();
    assert!(!phish_url.is_https()); // Not secure
    assert!(phish_url.host().unwrap().contains("fake"));
    assert_eq!(phish_url.path().unwrap(), "/login");

    // C2 domain classification
    let c2_domain_field = FieldValue::str("malware.botnet.cc");
    let c2_domain = c2_domain_field.as_domain().unwrap();
    assert_eq!(c2_domain.tld(), "cc"); // Suspicious TLD
    assert_eq!(c2_domain.sld().unwrap(), "botnet");
}

#[test]
fn test_email_security_patterns() {
    let emails = vec![
        ("admin@company.com", true, "company.com"),
        ("user@gmail.com", false, "gmail.com"),
        ("security@internal.corp.com", true, "corp.com"),
        ("suspicious@temp-mail.org", false, "temp-mail.org"),
    ];

    for (email_str, is_internal, expected_domain) in emails {
        let field = FieldValue::str(email_str);
        let email = field.as_email().unwrap();

        // Check if it's from internal domains (basic heuristic)
        let is_corp_email =
            email.ends_with_domain("company.com") || email.ends_with_domain("corp.com");
        assert_eq!(is_corp_email, is_internal);

        // Verify domain extraction
        let domain = email.domain_parsed();
        assert!(domain.as_str().ends_with(expected_domain));
    }
}

#[test]
fn test_url_security_analysis() {
    let urls = vec![
        ("https://secure.bank.com/login", true, true),
        ("http://fake-bank.com/phish", false, false),
        ("https://legitimate.com", true, true),
        ("ftp://old-system.internal.com", false, false),
    ];

    for (url_str, is_secure_scheme, is_https) in urls {
        let field = FieldValue::str(url_str);
        let url = field.as_url().unwrap();

        assert_eq!(url.is_https(), is_https);

        let has_secure_scheme = url.is_https() || url.scheme().map_or(false, |s| s == "https");
        assert_eq!(has_secure_scheme, is_secure_scheme);
    }
}
