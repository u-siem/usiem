# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Project overview

**uSIEM** is a modular, high-performance SIEM (Security Information and Event
Management) framework written in Rust. It is a **library crate** — there is no
binary and nothing to "run" — providing the core building blocks (event
model, parsers, enrichment, a processing pipeline, and framework-only
interfaces for I/O) for constructing custom SIEM solutions. Correlation/rule
logic is deliberately out of scope — see the "trait-shape conventions" note
below. MIT licensed.

## Tech stack

- Rust, **edition 2024** — requires a fairly recent toolchain (Rust ≥ 1.85).
  There is no `rust-toolchain.toml`, so whatever toolchain you have installed
  must support edition 2024.
- Single Cargo crate, **no workspace**, no other packages to worry about.
- Dependencies: `time`, `regex`, `smallvec` (small-map storage for
  `FieldMap`), `compact_str` (backs `Text` — inline up to 24 bytes on
  64-bit, a real heap-backed buffer beyond that, with genuine in-place
  mutation via `DerefMut`/`push_str`/etc.). All four were picked
  specifically for having near-zero required transitive dependencies of
  their own — adding a named crate is fine, adding a deep dependency tree
  is not. `compact_str` was chosen over `smol_str` (an earlier revision's
  choice) deliberately: `smol_str` is immutable by design (its cheap
  `Arc`-shared clone depends on that), which would block a future parser
  that needs to mutate an already-stored field value in place; `compact_str`
  trades that O(1) clone for real mutability, since a demonstrated future
  need for mutation was judged more likely than needing the cheaper clone
  for long (>24 byte) values. Optional (feature-gated): `serde`,
  `serde_json` — enabling `serde` also turns on `compact_str/serde`
  (`FieldValue::Object`'s `HashMap<Text, FieldValue>` needs `Text:
  Serialize`/`Deserialize` for `HashMap`'s own impl to apply; this isn't
  skippable the way it looks at first). Dev-dependencies: `criterion`
  (benchmarks), `serde_json` (unconditional — used by `#[cfg(feature =
  "serde")]` tests as a concrete serde format, independent of the `json`
  feature).
- **`CompactString: AsRef<_>` is ambiguous where `Cow<'static, str>`
  wasn't** — it implements `AsRef<str>`, `AsRef<[u8]>`, `AsRef<OsStr>`,
  `AsRef<Path>`. Bare `.as_ref()` on a `Text`/`CompactString` value needs
  an explicit `let x: &str = value.as_ref();` (or an unambiguous call
  site) — a bare `x.as_ref() == y` will fail to compile with "type
  annotations needed."
- **No logging/tracing dependency** — `src/observability.rs` is a small
  hand-rolled facade instead (see below). This was a deliberate choice:
  "as few external crates as possible."

## Commands

```
cargo build                      # build with default features
cargo build --all-features
cargo check --all-features       # do this before trusting a change compiles
cargo test                       # unit + integration tests, default features
cargo test --all-features        # required to exercise serde/json-gated tests
cargo test --test <file>         # run one integration-test file, e.g. field_integration_tests
cargo test <name> -- --exact     # run one test by exact name
cargo bench                      # all criterion benchmarks
cargo bench --bench <name>       # parse_benchmarks | parse_transport_benchmarks | field_benchmarks
cargo fmt
cargo clippy --all-features --all-targets
```

CI (`.github/workflows/ci.yml`) runs `cargo build`/`cargo test` across all 4
feature combinations (none, `serde`, `json`, `--all-features`), plus
`cargo fmt --check` and `cargo clippy`. Keep the repo fmt-clean and
clippy-clean (no hard errors) — there's no `rustfmt.toml`/`clippy.toml`, so
defaults apply.

## Repo layout

```
src/
├── lib.rs                  # crate root: pub mod event/ingest/observability/processing + `prelude`
├── observability.rs         # minimal dependency-free logging facade (Logger trait, log_*! macros)
├── event/                   # core data model: Event (core.rs, aliased CoreEvent — see gotcha below),
│                            # RawEvent, FieldValue (typed field system), Origin, EventId, Schema,
│                            # FieldMap (field/field_map.rs — a named bag of FieldValues, SmallVec-
│                            # backed for small-N linear-scan lookup, Text-keyed so literal keys cost
│                            # no allocation; used by Action's params/result data) + FieldLookup (the
│                            # get(&str)-only trait Schema's validator uses to accept both HashMap and
│                            # FieldMap without depending on either concretely)
├── ingest/
│   ├── collector.rs         # Collector trait — framework interface only, no concrete collectors
│   └── parser/              # LogParser, ParserRegistry, common (Apache/JSON/Windows/CEF) +
│                            # transport/syslog parsers
└── processing/
    ├── metadata.rs          # unimplemented stub — do NOT confuse with src/event/metadata.rs (real code)
    ├── pipeline.rs          # Pipeline/Processor: ordered, instrumented processing stages
    ├── signal.rs            # Signal: an event/cluster evaluated against context or threat intel
    │                        # and flagged suspicious — not yet an alarm (Signal::into_event)
    ├── incident.rs          # Incident: analyst-facing aggregate of events/signals judged
    │                        # significant by an application-defined rule (Incident::into_event)
    ├── sink.rs              # Sink trait — framework interface only, no concrete sinks
    ├── action.rs            # Action trait + ActionRegistry: the SIEM's one self-describing
    │                        # interaction surface (response actions, admin commands, and
    │                        # read-only queries alike) — a capability name can have many
    │                        # registered providers; ActionRegistry::invoke fans out to all
    └── enrichment/          # fully built-out dataset/registry/manager framework (~2900 LOC)
tests/                       # black-box integration tests against the public API
examples/                    # basic_pipeline.rs: full parse -> pipeline -> correlate -> signal ->
                             # incident -> sink walkthrough; run with `cargo run --example basic_pipeline`
benches/                     # Criterion benchmarks (harness = false)
```

## Code conventions

- Standard Rust naming: `snake_case` items, `PascalCase` types, `SCREAMING_SNAKE_CASE` consts.
- Rustdoc (`///`, `//!`) on public items. Complex modules (mainly under
  `processing/enrichment/`) follow a `# Architecture` / `# Design Philosophy`
  / `# Usage Examples` doc template with fenced examples marked
  ` ```rust,no_compile,no_run ` — these are illustrative, not real doctests,
  and are intentionally skipped by `cargo test --doc`. Simpler modules
  (`pipeline`, `sink`, `collector`, `observability`) have real,
  compiled-and-run doctests instead — prefer that when the example doesn't
  need a hypothetical external type.
- **No `thiserror`/`anyhow`.** Every fallible domain has its own hand-written
  error enum implementing `Display` + `Error` (`FieldConversionError`,
  `EnrichmentError`, `ParsingError`, `SchemaError`, etc.). Follow this pattern
  for new error types rather than introducing a crate. There is no unified
  top-level error type by design; only add a cross-module `From` impl when a
  real call site needs it (e.g. `FieldConversionError -> ParsingError`) —
  don't add speculative conversions between domains that never actually compose.
- **No logging/tracing crate.** Use `crate::log_error!`/`log_warn!`/`log_info!`/
  `log_debug!`/`log_trace!` (defined in `src/observability.rs`) for internal
  instrumentation. These no-op (without even formatting the message) unless
  an application installs a `Logger` via `usiem::observability::set_logger`.
- Enums are the primary tagged-union tool (`FieldValue`, `RawData`, `Origin`,
  `ParseResult`, `ProcessResult`, ...). Builders use a consuming-`self` fluent
  style (`ObjectBuilder`, `SchemaFieldBuilder`, `DatasetBuilder`).
- **Two different trait-shape conventions, used deliberately:**
  - Stateless, hot-path stages are plain `fn` pointers, **not** `dyn Trait`
    (`LogParser`/`ParserFn`, `Processor`/`ProcessorFn`, `TransportParser`).
    Don't refactor these to trait objects.
  - Stateful external integrations (need to hold a socket, file handle,
    buffer, etc.) are traits implemented by the consumer, with no bundled
    implementation: `Collector` (ingest), `Sink` (output), `Logger`
    (observability), `GeoIpDataset`/`ThreatIntelDataset` (enrichment
    providers), `Action` (`processing/action.rs`). These mirror each other —
    follow this pattern for new "external thing plugs into the framework"
    extension points. `Action::execute` is the one deliberate deviation:
    `&self`, not `&mut self` — an action is expected to run concurrently
    (application code, a `Sink`'s side effect, and every other provider of
    the same capability via `ActionRegistry::invoke`, all at once), so any
    implementor-side mutable state must be interior mutability rather than
    relying on exclusive access. `Action`/`ActionRegistry` is meant to be
    the SIEM's *one* self-describing interaction surface — not just SOAR
    response actions (`"block_ip"`), but admin/config commands and
    read-only queries (`"search_logs"`) too, so an MCP server or an
    AI-driven UI/CLI has exactly one thing to discover and invoke. See
    `ActionDescriptor`'s `read_only`/`destructive`/`idempotent` fields
    (mirroring MCP's own tool annotations) before assuming this crate needs
    a separate query/search contract.
  - This crate deliberately has **no correlation/rule-engine API at all** —
    not a struct, not a trait. Detecting things like "5 failed logins from
    the same account within 60 seconds" is entirely application code (see
    `FailedLoginCounter` in `examples/basic_pipeline.rs` for one way to do
    it); there is likewise no built-in event deduplicator, since a
    content-hash dedup set (`HashSet<EventId>`) with no eviction policy
    grows without bound in a long-running process — that decision, and any
    bounding strategy (LRU, TTL, whatever fits the deployment), is left to
    the application. `Signal` (`signal.rs`) and `Incident` (`incident.rs`)
    are the detection *output* types — plain, application-constructed value
    types with no correlation logic of their own — see their module docs for
    how they relate (`Signal` states a fact, `Incident` is an independent,
    application-driven aggregate of events/signals).
- The enrichment subsystem intentionally uses two type systems side by side:
  generic `MapDataset<K, V>` for compile-time-typed access, and
  `dyn AnyDataset` + `downcast_ref` for runtime-erased registries. Both are
  documented as deliberate in `src/processing/enrichment/core.rs` — this is
  not duplication to clean up.
- No enforced import ordering (no rustfmt config exists) — don't impose one.

## A real naming footgun: `Event` vs `CoreEvent`

`crate::event::Event` (and `usiem::prelude::Event`) is a type alias for
`ObjectBuilder` (a fluent builder for `FieldValue::Object` trees) — **not**
the actual SIEM event struct. The real event type (`arrival_time`,
`original_time`, `origin`, `raw_data`, `fields`) lives in `src/event/core.rs`
and is re-exported as `CoreEvent` specifically to dodge this collision (see
`src/ingest/parser/result.rs:2` for the established `use crate::event::CoreEvent as Event;`
convention — follow it in new code rather than `use crate::event::Event;`).
This is a known, pre-existing wart, not something to "fix" by renaming either
type without a deliberate decision — that's a public-API-breaking change.

## Testing conventions

- Plain `#[test]`, no external test or mocking framework. Test doubles are
  hand-written structs implementing the relevant trait, not mocks.
- Inline `#[cfg(test)] mod tests { ... }` at the bottom of the file is the
  default. Larger suites live in a sibling file wired in via
  `#[cfg(test)] mod x;` in `mod.rs` (e.g. `src/event/field/command_line_tests.rs`).
- Integration tests (black-box, against the public API) live in top-level
  `tests/`, including `pipeline_integration_tests.rs`, which wires
  `ParserRegistry` and `Pipeline` together end-to-end — a useful template for
  testing across subsystem boundaries. `examples/basic_pipeline.rs` goes
  further (parse -> pipeline -> correlate -> signal -> incident -> sink) and
  is meant to be read, not just compiled — `cargo run --example basic_pipeline`
  actually executes it and prints/logs its own output.
- Some tests are feature-gated (`#[cfg(feature = "serde")]` /
  `#[cfg(feature = "json")]`) — use `cargo test --all-features` for full coverage.
- Tests that mutate process-global state (e.g. `observability`'s
  `LOGGER`/`MAX_LEVEL` statics) must live in a single `#[test]` function, not
  split across several — Rust's default parallel test runner will race
  otherwise. Look at `src/observability.rs`'s test module before adding more
  global-state tests.

## Known stubs — do not "clean up"

`src/processing/metadata.rs` is an intentional 1-line placeholder with no
documented design intent anywhere — leave it alone unless you're prepared to
design that from scratch (`src/processing/proxy.rs` was the other such stub;
it has since been removed rather than speculatively designed).
`src/ingest/parser/test.rs` is an empty, disabled test scaffold (its `mod
test;` is commented out in `parser/mod.rs`). None of these are dead code to
delete.

(`collector.rs` and `pipeline.rs` were previously stubs but are now real,
tested implementations — don't assume older commit messages/docs describing
them as empty are still accurate.)

## Git conventions

Commit messages so far use Conventional-Commits-style prefixes (`feat:`,
`fix:`) with short, lower-case, imperative summaries and no scopes or body
text. Follow that style. (History is short, so treat this as a light
convention rather than a strictly enforced rule.)

## Contributing

See the "Contributing" section in [README.md](README.md) for the fork/branch/PR workflow.
