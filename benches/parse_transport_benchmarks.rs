use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use usiem::event::Origin;
use usiem::ingest::parser::transport_parsers::{
    parse_file_transport, parse_syslog_rfc3164_transport, parse_syslog_rfc5424_transport,
};

/// Sample log entries for transport parsing benchmarking
const RFC3164_LOG: &str =
    r#"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"#;
const RFC5424_LOG: &str = r#"<165>1 2023-10-11T22:14:15.003Z mymachine evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry..."#;
const FILE_LOG: &str =
    r#"2023-10-11 22:14:15 [ERROR] Failed to connect to database: Connection timeout"#;

fn bench_transport_parsers(c: &mut Criterion) {
    let origin = Origin::from_source_string("192.168.1.1");

    let mut group = c.benchmark_group("transport_parsers");
    group.throughput(Throughput::Elements(1)); // Measure logs per second

    group.bench_function("rfc3164_transport", |b| {
        b.iter(|| {
            let result =
                parse_syslog_rfc3164_transport(black_box(RFC3164_LOG), black_box(origin.clone()));
            black_box(result);
        })
    });

    group.bench_function("rfc5424_transport", |b| {
        b.iter(|| {
            let result =
                parse_syslog_rfc5424_transport(black_box(RFC5424_LOG), black_box(origin.clone()));
            black_box(result);
        })
    });

    group.bench_function("file_transport", |b| {
        b.iter(|| {
            let result = parse_file_transport(black_box(FILE_LOG), black_box(origin.clone()));
            black_box(result);
        })
    });

    group.finish();
}

fn bench_transport_throughput(c: &mut Criterion) {
    let origin = Origin::from_source_string("192.168.1.1");

    let mut group = c.benchmark_group("transport_throughput");

    // RFC3164 throughput
    group.throughput(Throughput::Elements(1));
    group.bench_function("rfc3164_bytes_per_sec", |b| {
        b.iter(|| {
            let result =
                parse_syslog_rfc3164_transport(black_box(RFC3164_LOG), black_box(origin.clone()));
            black_box(result);
        })
    });

    // RFC5424 throughput (with structured data)
    group.throughput(Throughput::Elements(1));
    group.bench_function("rfc5424_structured_data", |b| {
        b.iter(|| {
            let result =
                parse_syslog_rfc5424_transport(black_box(RFC5424_LOG), black_box(origin.clone()));
            black_box(result);
        })
    });

    // File transport throughput
    group.throughput(Throughput::Elements(1));
    group.bench_function("file_transport_bytes_per_sec", |b| {
        b.iter(|| {
            let result = parse_file_transport(black_box(FILE_LOG), black_box(origin.clone()));
            black_box(result);
        })
    });

    group.finish();
}

fn bench_transport_registry(c: &mut Criterion) {
    use usiem::ingest::parser::transport_parsers::{
        file_transport_parser, syslog_rfc3164_transport_parser, syslog_rfc5424_transport_parser,
    };
    use usiem::ingest::parser::transport_registry::TransportRegistry;

    let mut group = c.benchmark_group("transport_registry");
    group.throughput(Throughput::Elements(3)); // 3 logs per iteration

    group.bench_function("transport_registry_adaptive", |b| {
        let origin = Origin::from_source_string("192.168.1.1");

        let mut transport_registry = TransportRegistry::new();
        transport_registry.register(syslog_rfc3164_transport_parser());
        transport_registry.register(syslog_rfc5424_transport_parser());
        transport_registry.register(file_transport_parser());

        let test_logs = vec![RFC3164_LOG, RFC5424_LOG, FILE_LOG];

        b.iter(|| {
            for log in &test_logs {
                let result = transport_registry.parse(black_box(log), black_box(origin.clone()));
                black_box(result);
            }
        })
    });

    group.finish();
}

fn bench_structured_data_parsing(c: &mut Criterion) {
    let origin = Origin::from_source_string("192.168.1.1");

    // Test RFC5424 with different levels of structured data complexity
    let simple_structured =
        r#"<165>1 2023-10-11T22:14:15.003Z host app - ID47 [test@123 key="value"] Simple message"#;
    let complex_structured = r#"<165>1 2023-10-11T22:14:15.003Z host app - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][meta@456 version="1.0" encoding="utf8"] Complex structured data message"#;

    let mut group = c.benchmark_group("structured_data");
    group.throughput(Throughput::Elements(1));

    group.bench_function("simple_structured_data", |b| {
        b.iter(|| {
            let result = parse_syslog_rfc5424_transport(
                black_box(simple_structured),
                black_box(origin.clone()),
            );
            black_box(result);
        })
    });

    group.bench_function("complex_structured_data", |b| {
        b.iter(|| {
            let result = parse_syslog_rfc5424_transport(
                black_box(complex_structured),
                black_box(origin.clone()),
            );
            black_box(result);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_transport_parsers,
    bench_transport_throughput,
    bench_transport_registry,
    bench_structured_data_parsing
);
criterion_main!(benches);
