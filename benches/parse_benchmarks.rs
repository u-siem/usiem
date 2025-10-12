use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use usiem::event::{Ip, Origin, RawEvent, Timestamp};
use usiem::ingest::parser::common_parsers::{
    apache_common_parser, parse_apache_common, parse_windows_event, windows_event_parser,
};

/// Sample log entries for benchmarking
const APACHE_LOG: &str =
    r#"192.168.1.100 - user [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024"#;
const WINDOWS_LOG: &str = r#"2023-10-11 22:14:15.003 [Security] Event ID: 4624 - An account was successfully logged on. User: admin, Logon Type: 3"#;

fn bench_content_parsers(c: &mut Criterion) {
    let origin = Origin::from_ip(Ip::from("192.168.1.1".parse::<std::net::IpAddr>().unwrap()));
    let timestamp = Timestamp::now();

    // Create RawEvents for content parsing
    let apache_raw = RawEvent::new(APACHE_LOG.to_string(), timestamp, origin.clone());
    let windows_raw = RawEvent::new(WINDOWS_LOG.to_string(), timestamp, origin.clone());

    let mut group = c.benchmark_group("content_parsers");
    group.throughput(Throughput::Elements(1)); // Measure logs per second

    group.bench_function("apache_common", |b| {
        b.iter(|| {
            let result = parse_apache_common(black_box(apache_raw.clone()));
            black_box(result);
        })
    });

    group.bench_function("windows_event", |b| {
        b.iter(|| {
            let result = parse_windows_event(black_box(windows_raw.clone()));
            black_box(result);
        })
    });

    group.finish();
}

fn bench_parser_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_creation");

    group.bench_function("apache_parser_factory", |b| {
        b.iter(|| {
            let parser = apache_common_parser();
            black_box(parser);
        })
    });

    group.bench_function("windows_parser_factory", |b| {
        b.iter(|| {
            let parser = windows_event_parser();
            black_box(parser);
        })
    });

    group.finish();
}

fn bench_registry_performance(c: &mut Criterion) {
    use usiem::ingest::parser::registry::ParserRegistry;

    let mut group = c.benchmark_group("registry_performance");
    group.throughput(Throughput::Elements(2)); // 2 logs per iteration

    // Content parser registry
    group.bench_function("content_registry_adaptive", |b| {
        let origin = Origin::from_ip(Ip::from("192.168.1.1".parse::<std::net::IpAddr>().unwrap()));
        let timestamp = Timestamp::now();

        let mut content_registry = ParserRegistry::new();
        content_registry.register(apache_common_parser());
        content_registry.register(windows_event_parser());

        let test_events = vec![
            RawEvent::new(APACHE_LOG.to_string(), timestamp, origin.clone()),
            RawEvent::new(WINDOWS_LOG.to_string(), timestamp, origin.clone()),
        ];

        b.iter(|| {
            for event in &test_events {
                let result = content_registry.parse(black_box(event.clone()));
                black_box(result);
            }
        })
    });

    group.finish();
}

fn bench_throughput_measurements(c: &mut Criterion) {
    let origin = Origin::from_ip(Ip::from("192.168.1.1".parse::<std::net::IpAddr>().unwrap()));
    let timestamp = Timestamp::now();

    let mut group = c.benchmark_group("throughput");

    // Set throughput measurement for different log sizes
    let small_log = APACHE_LOG; // ~80 bytes
    let large_log = &WINDOWS_LOG.repeat(3); // ~330 bytes

    group.throughput(Throughput::Bytes(small_log.len() as u64));
    group.bench_function("small_log_apache", |b| {
        let raw = RawEvent::new(small_log.to_string(), timestamp, origin.clone());
        b.iter(|| {
            let result = parse_apache_common(black_box(raw.clone()));
            black_box(result);
        })
    });

    group.throughput(Throughput::Bytes(large_log.len() as u64));
    group.bench_function("large_log_windows", |b| {
        let raw = RawEvent::new(large_log.to_string(), timestamp, origin.clone());
        b.iter(|| {
            let result = parse_windows_event(black_box(raw.clone()));
            black_box(result);
        })
    });

    group.finish();
}

fn bench_memory_usage_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");

    // Test zero-copy vs cloning patterns
    group.bench_function("zero_copy_raw_event", |b| {
        let origin = Origin::from_ip(Ip::from("192.168.1.1".parse::<std::net::IpAddr>().unwrap()));
        let timestamp = Timestamp::now();
        let raw = RawEvent::new(APACHE_LOG.to_string(), timestamp, origin);

        b.iter(|| {
            // Zero-copy: pass by value (no cloning)
            let parser = apache_common_parser();
            let result = (parser.parse_fn)(black_box(raw.clone()));
            black_box(result);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_content_parsers,
    bench_parser_creation,
    bench_registry_performance,
    bench_throughput_measurements,
    bench_memory_usage_patterns
);
criterion_main!(benches);
