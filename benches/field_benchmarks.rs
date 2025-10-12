use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::convert::TryInto;
use usiem::event::field::{FieldValue, Ip, Text, Timestamp};

fn bench_timestamp_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("timestamp_operations");
    group.throughput(Throughput::Elements(1));

    let rfc3339_strings = vec![
        "2025-10-11T10:30:00Z",
        "2025-10-11T10:30:00.123Z",
        "2025-10-11T10:30:00.123456Z",
        "2025-10-11T10:30:00.123456789Z",
        "2025-10-11T10:30:00+05:30",
    ];

    group.bench_function("timestamp_from_rfc3339", |b| {
        b.iter(|| {
            for time_str in &rfc3339_strings {
                let field = FieldValue::Str((*time_str).into());
                let _: Timestamp = black_box(field).try_into().unwrap();
            }
        })
    });

    group.bench_function("timestamp_from_nanos", |b| {
        b.iter(|| {
            let field = FieldValue::Int(1640995200_000_000_000);
            let _: Timestamp = black_box(field).try_into().unwrap();
        })
    });

    group.finish();
}

fn bench_ip_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ip_operations");
    group.throughput(Throughput::Elements(1));

    let ip_strings = vec![
        "192.168.1.1",
        "10.0.0.1",
        "172.16.254.1",
        "2001:db8::1",
        "::1",
        "fe80::1%lo0",
    ];

    group.bench_function("ip_parsing", |b| {
        b.iter(|| {
            for ip_str in &ip_strings {
                let field = FieldValue::Str((*ip_str).into());
                if let Ok(ip) = TryInto::<Ip>::try_into(black_box(field)) {
                    black_box(ip);
                }
            }
        })
    });

    group.finish();
}

fn bench_numeric_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("numeric_conversions");
    group.throughput(Throughput::Elements(1));

    let number_strings = vec!["42", "12345", "-9876", "3.14159", "2.71828"];

    group.bench_function("string_to_i64", |b| {
        b.iter(|| {
            for num_str in &number_strings[..3] {
                // Only integers
                let field = FieldValue::Str((*num_str).into());
                if let Ok(num) = TryInto::<i64>::try_into(black_box(field)) {
                    black_box(num);
                }
            }
        })
    });

    group.bench_function("string_to_f64", |b| {
        b.iter(|| {
            for num_str in &number_strings {
                let field = FieldValue::Str((*num_str).into());
                if let Ok(num) = TryInto::<f64>::try_into(black_box(field)) {
                    black_box(num);
                }
            }
        })
    });

    group.finish();
}

fn bench_text_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("text_operations");
    group.throughput(Throughput::Elements(1));

    group.bench_function("cow_static_str", |b| {
        b.iter(|| {
            let text: Text = black_box("static_string").into();
            let field = FieldValue::Str(text);
            let _: String = black_box(field).try_into().unwrap();
        })
    });

    group.bench_function("cow_owned_string", |b| {
        b.iter(|| {
            let text: Text = black_box(String::from("owned_string")).into();
            let field = FieldValue::Str(text);
            let _: String = black_box(field).try_into().unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_timestamp_operations,
    bench_ip_operations,
    bench_numeric_conversions,
    bench_text_operations
);
criterion_main!(benches);
