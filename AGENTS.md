# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Project overview

**uSIEM** is a modular, high-performance SIEM (Security Information and Event
Management) framework written in Rust. It is a **library crate** — there is no
binary and nothing to "run" — providing the core building blocks (event
model, parsers, enrichment, a processing pipeline and worker runtime,
detection output types, an action registry and RBAC-style authorization) for
constructing custom SIEM solutions. I/O (collection, storage, output),
correlation/rule logic and incident workflow are deliberately out of scope —
see "What is not in this crate" below. MIT licensed.

**Authorization is in scope; authentication is not.** `src/security/` ships
`Principal`/`Role`/`Permission`/`Authorizer` (plus a bundled static-RBAC
`RoleAuthorizer`) so `ActionRegistry::list_for`/`invoke_as` can filter
discovery and enforce invocation. It never sees a credential, token, or
network request — turning a real credential into a `Principal` is the
application's (or a transport crate's) job: a policy-free contract in
core, zero bundled I/O.

## What is not in this crate

Removed in 0.2 because no consumer used them and each application already
had a better-fitting type of its own. Don't re-add them speculatively; if a
second consumer needs the same thing, design it against both.

- **Collector / Sink traits.** Real inputs push with backpressure, cursors,
  progress and alarms; real outputs are event stores with batch append,
  sync and search. A one-event `collect()`/`send()` fit neither.
- **Incident.** Incidents carry workflow state (status, assignee, notes,
  merges) that each application models itself. `Signal` is the detection
  output that crosses crate boundaries.
- **CapabilityCatalog / MCP surface / TemplateRegistry.** Speculative
  infrastructure with no transport or client. An MCP server belongs in its
  own crate on top of `ActionRegistry` + `security`. Git history has the
  old code.
- **Enrichment manager and the ThreatInfo/AssetInfo/UserProfile value
  types.** Applications plug their own value types into
  `MapDataset`/`CidrDataset`/`NetworkDataset`; only `GeoIp`/`GeoIpDataset`
  is a shared provider interface.

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
  skippable the way it looks at first). `json` adds `serde_json` and
  `Schema::to_json_schema` (`src/event/json_schema.rs`). Dev-dependencies:
  `criterion` (benchmarks), `serde_json` (unconditional — used by
  `#[cfg(feature = "serde")]` tests as a concrete serde format, independent
  of the `json` feature).
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
├── lib.rs                  # crate root: pub mod event/ingest/observability/processing/security
│                            # + `prelude`
├── observability.rs         # minimal dependency-free logging facade (Logger trait, log_*! macros)
├── security/                # authorization ONLY, not authentication — Principal/PrincipalKind/Role/
│                            # Permission/PermissionPattern/Authorizer/RoleAuthorizer/AllowAll/Decision.
│                            # Never sees a credential/token/request; ActionRegistry::list_for/invoke_as
│                            # are the only consumers in this crate.
├── event/                   # core data model: Event (core.rs; see "Event vs ObjectBuilder" below),
│                            # RawEvent, FieldValue (typed field system), Origin, EventId, Schema
│                            # (+ json_schema.rs, feature `json`: Schema::to_json_schema),
│                            # hash.rs: StableHasher (FNV-1a over an explicit encoding) behind every
│                            # persisted id — never use DefaultHasher/std Hash for stored ids,
│                            # fields.rs: well-known (ECS + forensic-rs artifact.*) field-name
│                            # constants — optional, nothing enforces them;
│                            # json_interop.rs (feature `json`): FieldValue::from_json + JsonValue interop;
│                            # FieldMap (field/field_map.rs — a named bag of FieldValues, SmallVec-
│                            # backed for small-N linear-scan lookup, Text-keyed so literal keys cost
│                            # no allocation; used by Action's params/result data) + FieldLookup (the
│                            # get(&str)-only trait Schema's validator uses to accept both HashMap and
│                            # FieldMap without depending on either concretely)
├── ingest/
│   ├── framing.rs           # SyslogFramer: sans-IO RFC 6587 splitter (octet counting + LF framing,
│   │                        # detected per message) — callers own the sockets
│   └── parser/              # LogParser, ParserRegistry, common (Apache/JSON/Windows/CEF) +
│                            # transport/syslog parsers + TransportRegistry; both registries parse
│                            # through &self (learned order in priorities.rs, an RwLock'd map).
│                            # Parsers for particular sources live outside this crate; common and
│                            # transport parsers are earlier exceptions, not a place for new ones

└── processing/
    ├── context.rs           # InvocationContext (who's calling + tenant/request_id/reason/cancellation),
    │                        # threaded through every Action::execute call
    ├── pipeline.rs          # Pipeline/Processor: ordered stages run through &self, with cumulative
    │                        # per-stage atomic StageStats (runs/drops/errors/time)
    ├── rating.rs            # shared rating scales: Severity (+ Criticality/RiskLevel aliases,
    │                        # from_score for 1-10 feeds), Confidence (0..=100) and RiskScore
    │                        # (saturating risk points); signal.rs re-exports Severity/Confidence
    │                        # for the old processing::signal paths
    ├── entity.rs            # EntityKind/EntityRef: the host/user/ip/device a finding is about,
    │                        # normalised; EntityKind::for_field maps ECS field names to kinds.
    │                        # Naming only — risk totals and grouping are application logic
    ├── signal.rs            # Signal: an event/cluster evaluated against context or threat intel
    │                        # and flagged suspicious — not yet an alarm (Signal::into_event)
    ├── workers.rs           # std-only runtime: bounded MPMC Queue (try_push for async producers,
    │                        # pop_batch with linger) + WorkerPool (one Worker per named thread,
    │                        # panics restart the worker). Processing is sync; async I/O is the host's
    ├── lookup.rs            # async-I/O lookups without .await in stages: LookupPoint parks cache
    │                        # misses, the host resolves them through AsyncLookup (returns a std Future),
    │                        # complete() resumes them; SegmentedPipeline = Pipelines between points;
    │                        # LookupCache (TTL + negative), Budget, CircuitBreaker, LookupDriver
    ├── action.rs            # Action trait + ActionRegistry: the SIEM's one self-describing
    │                        # interaction surface (response actions, admin commands, and
    │                        # read-only queries alike) — a capability name can have many
    │                        # registered providers; ActionRegistry::invoke/invoke_as fan out to
    │                        # all (list_for/invoke_as consult a security::Authorizer and enforce +
    │                        # unconditionally audit; invoke/list stay unauthenticated, for trusted
    │                        # in-process callers)
    └── enrichment/          # dataset/registry framework; GeoIp + GeoIpDataset (the one shared provider
                             # interface); domain.rs: DomainSet; cidr.rs: CidrDataset, the one bundled NetworkDataset (in-memory
                             # longest-prefix table for blocklists/zones). NetworkDataset::lookup_by_ip
                             # returns Option<Cow<V>> so on-disk readers (mmdb) can return owned values
tests/                       # black-box integration tests against the public API
examples/                    # basic_pipeline.rs: parse -> pipeline -> correlate -> signal walkthrough;
                             # action_firing.rs / command_surface.rs: ActionRegistry; rbac.rs:
                             # RoleAuthorizer filtering discovery + gating invocation, agent-vs-human
                             # approval; schema_validation.rs. Run any with `cargo run --example <name>`.
benches/                     # Criterion benchmarks (harness = false)
```

## Code conventions

- Standard Rust naming: `snake_case` items, `PascalCase` types, `SCREAMING_SNAKE_CASE` consts.
- Rustdoc (`///`, `//!`) on public items. Complex modules (mainly under
  `processing/enrichment/`) follow a `# Architecture` / `# Design Philosophy`
  / `# Usage Examples` doc template with fenced examples marked
  ` ```rust,no_compile,no_run ` — these are illustrative, not real doctests,
  and are intentionally skipped by `cargo test --doc`. Simpler modules
  (`pipeline`, `lookup`, `observability`) have real,
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
  style (`ObjectBuilder`, `SchemaFieldBuilder`, `ActionDescriptorBuilder`).
- **Typed values, not raw integers.** Every wall-clock instant is a
  `Timestamp` (`event/field/time.rs`, i64 ns UTC) — including enrichment
  dates and schema metadata. Severity, business criticality and account risk
  are `processing::rating::Severity` (`Criticality`/`RiskLevel` are aliases);
  certainty is `processing::rating::Confidence`. `std::time::Instant` in
  `lookup.rs`/`workers.rs` is a monotonic timer, not a datetime — leave it.
- **Persisted ids are stable hashes.** `EventId`/`SignalId` are computed
  with `event::hash::StableHasher` over an explicit byte encoding, and pinned
  by golden-value tests. If a golden test fails, revert the change — don't
  update the constant: stored data links by these ids. Events read back from
  storage should use `Event::stored_or_computed_id`.
- **Two different trait-shape conventions, used deliberately:**
  - Hot-path stages are an identity (`id`/`name`/`description`) plus a
    shared closure, `Arc<dyn Fn(..) + Send + Sync>` (`LogParser`/`ParserFn`,
    `Processor`/`ProcessorFn`, `TransportParser`/`TransportParserFn`,
    `LookupSpec`'s `KeyFn`/`ApplyFn`). Constructors take `impl Fn`, so a
    plain `fn` item and a closure capturing configuration both work. Don't
    turn these into traits; don't go back to bare `fn` pointers (they forced
    consumers into globals for configuration).
  - Stateful external integrations are traits implemented by the
    consumer, with no bundled implementation: `Logger` (observability),
    `GeoIpDataset`/`NetworkDataset`/`AnyDataset` (enrichment), `AsyncLookup`
    (lookup), `Worker` (workers), `Action` (`processing/action.rs`).
    `Action::execute` takes `&self`, not `&mut self` — an action is expected
    to run concurrently (application code, an output's side effect, and every other
    provider of the same capability via `ActionRegistry::invoke`, all at
    once), so any implementor-side mutable state must be interior mutability
    rather than relying on exclusive access. Its signature is
    `execute(&self, ctx: &processing::context::InvocationContext, params:
    &FieldMap)` — `ctx` identifies the caller (see `security::Principal`) and
    carries tenant/request-id/cancellation, but is *not* itself an
    authorization check; only `ActionRegistry::invoke_as` (via a
    `security::Authorizer`) enforces one. `Action`/`ActionRegistry` is meant
    to be the SIEM's *one* self-describing interaction surface — not just
    SOAR response actions (`"block_ip"`), but admin/config commands and
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
    the application. `Signal` (`signal.rs`) is the detection *output*
    type — a plain, application-constructed value with no correlation logic
    of its own. Alerts and incidents built from signals are application
    types.
- The enrichment subsystem intentionally uses two type systems side by side:
  generic `MapDataset<K, V>` for compile-time-typed access, and
  `dyn AnyDataset` + `downcast_ref` for runtime-erased registries. Both are
  documented as deliberate in `src/processing/enrichment/core.rs` — this is
  not duplication to clean up.
- No enforced import ordering (no rustfmt config exists) — don't impose one.

## `Event` vs `ObjectBuilder` (and the old `CoreEvent`)

`usiem::event::Event` is the SIEM event struct (`arrival_time`,
`original_time`, `origin`, `raw_data`, `fields`, in `src/event/core.rs`).
The fluent builder for `FieldValue::Object` trees is `ObjectBuilder` only.
Until 0.2 `Event` named the builder and the struct was re-exported as
`CoreEvent`; `CoreEvent` survives as a `#[deprecated]` alias for one release
so `use usiem::event::CoreEvent as Event;` keeps compiling. New code imports
`usiem::event::Event`.

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
  further (parse -> pipeline -> correlate -> signal) and
  is meant to be read, not just compiled — `cargo run --example basic_pipeline`
  actually executes it and prints/logs its own output.
- Some tests are feature-gated (`#[cfg(feature = "serde")]` /
  `#[cfg(feature = "json")]`) — use `cargo test --all-features` for full coverage.
- Tests that mutate process-global state (e.g. `observability`'s
  `LOGGER`/`MAX_LEVEL` statics) must live in a single `#[test]` function, not
  split across several — Rust's default parallel test runner will race
  otherwise. Look at `src/observability.rs`'s test module before adding more
  global-state tests.

## Git conventions

Commit messages use Conventional-Commits-style prefixes (`feat:`, `fix:`,
`feat!:` for breaking changes) with short, lower-case, imperative summaries
and no scopes; a body is fine when the why isn't obvious. Follow that style. (History is short, so treat this as a light
convention rather than a strictly enforced rule.)

## Contributing

See the "Contributing" section in [README.md](README.md) for the fork/branch/PR workflow.
