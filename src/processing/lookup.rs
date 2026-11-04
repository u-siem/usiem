//! Lookups whose answer may need async I/O (a DNS query, an HTTP API),
//! without putting `.await` in the pipeline.
//!
//! # Design
//!
//! Pipeline stages stay synchronous. A [`LookupPoint`] is a place between
//! two pipeline segments where an event may *leave the pipeline and come
//! back*:
//!
//! 1. [`LookupPoint::process`] extracts the event's key with the
//!    [`LookupSpec::key`] fn. No key: the event continues untouched.
//! 2. On a [`LookupCache`] hit, [`LookupSpec::apply`] enriches the event
//!    synchronously and it continues.
//! 3. On a miss the event is *parked*. The first event parked for a key
//!    queues a request for that key, so K events with the same key cost one
//!    lookup. The host is told through the notifier set with
//!    [`LookupPoint::set_notifier`].
//! 4. The host's async side takes requests with
//!    [`LookupPoint::take_requests`] (or through a [`LookupDriver`]), runs
//!    [`AsyncLookup::resolve_batch`], and hands the answers to
//!    [`LookupPoint::complete`]. That fills the cache and moves the parked
//!    events to the point's *resumed* queue.
//! 5. Sync workers take resumed events back with
//!    [`SegmentedPipeline::drain_resumed`], which continues them in the next
//!    segment.
//!
//! Every outcome is recorded on the event as `enrichment.<name>.status`
//! (`ok`, `not_found`, `timeout`, `bypassed`, `failed`), plus
//! `enrichment.<name>.at` when an answer was applied, so a later query shows
//! what was known at ingest time. An event never waits longer than
//! [`LookupSpec::deadline`]: past it, [`LookupPoint::expire`] releases it
//! with `timeout`. When [`LookupSpec::max_parked`] events are already
//! waiting, new misses continue at once with `bypassed`: the pipeline is
//! never blocked by a slow service.
//!
//! This module is std-only. [`AsyncLookup`] returns a plain
//! `std::future::Future`; the host application decides which runtime
//! polls it. Budgets and circuit breaking are small sync state machines
//! ([`Budget`], [`CircuitBreaker`]) that a [`LookupDriver`] applies before
//! each request.
//!
//! Resumed events come back in completion order, not arrival order. Stages
//! after a lookup point must not assume arrival order.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use std::time::Duration;
//! use usiem::event::{CoreEvent as Event, FieldValue, Origin, RawData, Timestamp};
//! use usiem::processing::lookup::{
//!     LookupKey, LookupPoint, LookupResult, LookupSpec, Outcome, SegmentedPipeline,
//! };
//! use usiem::processing::pipeline::{Pipeline, ProcessResult};
//!
//! fn key(event: &Event) -> Option<LookupKey> {
//!     match event.get_field("source.ip") {
//!         Some(FieldValue::Str(ip)) => Some(ip.clone()),
//!         _ => None,
//!     }
//! }
//! fn apply(event: &mut Event, value: Option<&FieldValue>) {
//!     if let Some(name) = value {
//!         event.add_field("source.domain".into(), name.clone());
//!     }
//! }
//!
//! let rdns = Arc::new(LookupPoint::new(LookupSpec::new("rdns", "Reverse DNS", key, apply)));
//! let mut pipeline = SegmentedPipeline::new(Pipeline::new()).then_lookup(rdns.clone(), Pipeline::new());
//!
//! let mut event = Event::new(
//!     Timestamp::now(),
//!     Timestamp::now(),
//!     Origin::from_hostname("fw"),
//!     RawData::from_text("..."),
//! );
//! event.add_field("source.ip".into(), FieldValue::Str("192.0.2.7".into()));
//! assert!(matches!(pipeline.run(event), Outcome::Parked));
//!
//! // The host's async side would do this after awaiting the resolver.
//! let keys = rdns.take_requests(100);
//! rdns.complete(
//!     keys.into_iter()
//!         .map(|k| (k, LookupResult::found(FieldValue::Str("host.example".into()), Duration::from_secs(300))))
//!         .collect(),
//! );
//!
//! let resumed = pipeline.drain_resumed(100);
//! let ProcessResult::Continue(event) = &resumed[0] else { panic!() };
//! assert_eq!(event.get_field("source.domain"), Some(&FieldValue::Str("host.example".into())));
//! ```

use crate::event::CoreEvent as Event;
use crate::event::field::{FieldValue, Text, Timestamp};
use crate::processing::pipeline::{Pipeline, ProcessResult};
use crate::processing::workers::{PushError, Queue};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// What a lookup is keyed by: an IP, a domain, a hash, a MAC… as text.
pub type LookupKey = Text;

/// Extracts the lookup key from an event, or `None` to skip the lookup.
/// This is also the pre-filter: return `None` for events that should never
/// reach the service (private IPs, internal domains, uninteresting events).
pub type KeyFn = fn(&Event) -> Option<LookupKey>;

/// Writes a lookup answer into the event. `None` means the service had no
/// answer for the key (a negative result).
pub type ApplyFn = fn(&mut Event, Option<&FieldValue>);

/// One key's answer from an [`AsyncLookup`].
#[derive(Debug, Clone, PartialEq)]
pub enum LookupResult {
    /// The service answered; cache the value for `ttl`.
    Found { value: FieldValue, ttl: Duration },
    /// The service has no answer for this key; cache that for `ttl`.
    NotFound { ttl: Duration },
    /// The request failed. Nothing is cached; waiting events continue with
    /// `failed`.
    Failed(String),
    /// The driver chose not to ask (for example, a private IP while
    /// [`LookupPolicy::send_private_ips`] is off). Nothing is cached;
    /// waiting events continue with `bypassed`.
    Skipped,
}

impl LookupResult {
    /// Shorthand for [`LookupResult::Found`].
    pub fn found(value: FieldValue, ttl: Duration) -> Self {
        LookupResult::Found { value, ttl }
    }

    /// Shorthand for [`LookupResult::NotFound`].
    pub fn not_found(ttl: Duration) -> Self {
        LookupResult::NotFound { ttl }
    }
}

/// The outcome recorded in `enrichment.<name>.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupStatus {
    /// An answer was applied.
    Ok,
    /// The service had no answer.
    NotFound,
    /// The event waited past the deadline.
    Timeout,
    /// The lookup was skipped: too many events waiting, the point shut down,
    /// or the driver skipped the key.
    Bypassed,
    /// The request failed.
    Failed,
}

impl LookupStatus {
    /// The value stored in the status field.
    pub fn as_str(self) -> &'static str {
        match self {
            LookupStatus::Ok => "ok",
            LookupStatus::NotFound => "not_found",
            LookupStatus::Timeout => "timeout",
            LookupStatus::Bypassed => "bypassed",
            LookupStatus::Failed => "failed",
        }
    }
}

/// What the cache knows about a key.
#[derive(Debug, Clone, PartialEq)]
pub enum Cached {
    /// A cached answer.
    Found(FieldValue),
    /// A cached negative answer.
    NotFound,
    /// Nothing cached, or the entry expired.
    Miss,
}

struct CacheEntry {
    value: Option<FieldValue>,
    expires: Instant,
}

/// A bounded TTL cache of lookup answers, including negative ones.
///
/// When full, expired entries are purged first; if it is still full, the
/// half of the entries closest to expiry are evicted.
pub struct LookupCache {
    entries: Mutex<HashMap<LookupKey, CacheEntry>>,
    capacity: usize,
}

impl LookupCache {
    /// A cache holding at most `capacity` keys (minimum 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<LookupKey, CacheEntry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Look a key up as of `now`.
    pub fn get(&self, key: &str, now: Instant) -> Cached {
        match self.lock().get(key) {
            Some(entry) if entry.expires > now => match &entry.value {
                Some(value) => Cached::Found(value.clone()),
                None => Cached::NotFound,
            },
            _ => Cached::Miss,
        }
    }

    /// Store an answer (`None` for a negative one) for `ttl` from `now`.
    pub fn insert(&self, key: LookupKey, value: Option<FieldValue>, ttl: Duration, now: Instant) {
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.expires > now);
            if entries.len() >= self.capacity {
                let mut expiries: Vec<Instant> = entries.values().map(|e| e.expires).collect();
                let middle = expiries.len() / 2;
                let (_, cutoff, _) = expiries.select_nth_unstable(middle);
                let cutoff = *cutoff;
                entries.retain(|_, entry| entry.expires > cutoff);
            }
        }
        entries.insert(
            key,
            CacheEntry {
                value,
                expires: now + ttl,
            },
        );
    }

    /// Keys currently stored, expired or not.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

/// The static description of a lookup point.
#[derive(Clone, Copy)]
pub struct LookupSpec {
    /// Stable name, used in the `enrichment.<name>.*` fields.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Key extractor and pre-filter.
    pub key: KeyFn,
    /// Writes an answer into the event.
    pub apply: ApplyFn,
    /// The longest an event may stay parked.
    pub deadline: Duration,
    /// The most events waiting (parked or resumed but not yet drained);
    /// misses beyond this continue with `bypassed`.
    pub max_parked: usize,
    /// Cache capacity, in keys.
    pub cache_capacity: usize,
}

impl LookupSpec {
    /// A spec with a 2 s deadline, room for 10 000 waiting events and a
    /// 100 000-key cache.
    pub fn new(name: &'static str, description: &'static str, key: KeyFn, apply: ApplyFn) -> Self {
        Self {
            name,
            description,
            key,
            apply,
            deadline: Duration::from_secs(2),
            max_parked: 10_000,
            cache_capacity: 100_000,
        }
    }

    /// Set [`LookupSpec::deadline`].
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Set [`LookupSpec::max_parked`] (minimum 1).
    pub fn with_max_parked(mut self, max_parked: usize) -> Self {
        self.max_parked = max_parked.max(1);
        self
    }

    /// Set [`LookupSpec::cache_capacity`].
    pub fn with_cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = capacity;
        self
    }
}

/// Counters for one [`LookupPoint`].
#[derive(Debug, Default)]
pub struct LookupStats {
    /// Events answered from the cache.
    pub hits: AtomicU64,
    /// Events that parked.
    pub parked: AtomicU64,
    /// Keys requested from the async side.
    pub requests: AtomicU64,
    /// Events released with `ok` or `not_found` after a lookup.
    pub resolved: AtomicU64,
    /// Events released with `timeout`.
    pub timeouts: AtomicU64,
    /// Events that continued with `bypassed`.
    pub bypassed: AtomicU64,
    /// Events released with `failed`.
    pub failed: AtomicU64,
}

/// What happened to an event at a [`LookupPoint`].
#[derive(Debug)]
pub enum Step {
    /// The event continues now (enriched, skipped or bypassed).
    Continue(Event),
    /// The event is waiting for an answer; it will come back through
    /// [`LookupPoint::pop_resumed`].
    Parked,
}

#[derive(Default)]
struct Parking {
    by_key: HashMap<LookupKey, Vec<(Event, Instant)>>,
    count: usize,
}

/// A point between two pipeline segments where events may wait for an
/// async lookup. Shared (`Arc`) by every worker thread and the async driver.
pub struct LookupPoint {
    spec: LookupSpec,
    cache: LookupCache,
    parking: Mutex<Parking>,
    requests: Queue<LookupKey>,
    resumed: Queue<Event>,
    notifier: OnceLock<Box<dyn Fn() + Send + Sync>>,
    stats: LookupStats,
}

impl LookupPoint {
    /// A lookup point for `spec`.
    pub fn new(spec: LookupSpec) -> Self {
        // At most `max_parked` events wait, so `resumed` cannot overflow. A
        // requested key can outlive its events (they time out before the
        // driver takes it), so `requests` gets headroom; if it still fills
        // up, new misses continue as `bypassed`.
        Self {
            cache: LookupCache::new(spec.cache_capacity),
            parking: Mutex::new(Parking::default()),
            requests: Queue::new(spec.max_parked.saturating_mul(2)),
            resumed: Queue::new(spec.max_parked),
            notifier: OnceLock::new(),
            stats: LookupStats::default(),
            spec,
        }
    }

    /// Set the callback run (from a sync worker thread) whenever a new key
    /// is requested. It must not block: wake an async task, nothing more
    /// (e.g. `tokio::sync::Notify::notify_one`). Only the first call has an
    /// effect.
    pub fn set_notifier(&self, notifier: impl Fn() + Send + Sync + 'static) {
        let _ = self.notifier.set(Box::new(notifier));
    }

    /// The point's name.
    pub fn name(&self) -> &'static str {
        self.spec.name
    }

    /// The point's spec.
    pub fn spec(&self) -> &LookupSpec {
        &self.spec
    }

    /// The point's cache. Hosts may pre-warm it.
    pub fn cache(&self) -> &LookupCache {
        &self.cache
    }

    /// The point's counters.
    pub fn stats(&self) -> &LookupStats {
        &self.stats
    }

    fn lock(&self) -> MutexGuard<'_, Parking> {
        self.parking.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn mark(&self, event: &mut Event, status: LookupStatus) {
        event.add_field(
            format!("enrichment.{}.status", self.spec.name),
            FieldValue::Str(status.as_str().into()),
        );
    }

    fn answer(&self, event: &mut Event, value: Option<&FieldValue>) {
        (self.spec.apply)(event, value);
        event.add_field(
            format!("enrichment.{}.at", self.spec.name),
            FieldValue::Time(Timestamp::now()),
        );
        let status = if value.is_some() {
            LookupStatus::Ok
        } else {
            LookupStatus::NotFound
        };
        self.mark(event, status);
    }

    /// Run the lookup for one event. Called by sync worker threads.
    pub fn process(&self, mut event: Event) -> Step {
        let Some(key) = (self.spec.key)(&event) else {
            return Step::Continue(event);
        };
        let now = Instant::now();
        match self.cache.get(&key, now) {
            Cached::Found(value) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                self.answer(&mut event, Some(&value));
                return Step::Continue(event);
            }
            Cached::NotFound => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                self.answer(&mut event, None);
                return Step::Continue(event);
            }
            Cached::Miss => {}
        }

        let mut parking = self.lock();
        if parking.count + self.resumed.len() >= self.spec.max_parked {
            drop(parking);
            self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
            self.mark(&mut event, LookupStatus::Bypassed);
            return Step::Continue(event);
        }
        let first = match parking.by_key.entry(key.clone()) {
            Entry::Occupied(mut waiting) => {
                waiting.get_mut().push((event, now));
                false
            }
            Entry::Vacant(slot) => {
                slot.insert(vec![(event, now)]);
                true
            }
        };
        parking.count += 1;
        if first {
            if let Err(e) = self.requests.try_push(key) {
                // Closed (shut down), or full of stale requests.
                let key = e.into_inner();
                let mut waiting = parking.by_key.remove(&key).unwrap_or_default();
                parking.count -= waiting.len();
                drop(parking);
                let (mut event, _) = waiting.pop().expect("the event just parked");
                self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
                self.mark(&mut event, LookupStatus::Bypassed);
                return Step::Continue(event);
            }
            drop(parking);
            self.stats.requests.fetch_add(1, Ordering::Relaxed);
            if let Some(notify) = self.notifier.get() {
                notify();
            }
        }
        self.stats.parked.fetch_add(1, Ordering::Relaxed);
        Step::Parked
    }

    /// Take up to `max` requested keys without blocking. For the async side.
    pub fn take_requests(&self, max: usize) -> Vec<LookupKey> {
        self.requests.try_pop_batch(max)
    }

    /// Keys requested and not yet taken.
    pub fn pending_requests(&self) -> usize {
        self.requests.len()
    }

    /// Events currently parked.
    pub fn parked_len(&self) -> usize {
        self.lock().count
    }

    fn release(&self, parking: &mut Parking, key: &str) -> Vec<Event> {
        match parking.by_key.remove(key) {
            Some(waiting) => {
                parking.count -= waiting.len();
                waiting.into_iter().map(|(event, _)| event).collect()
            }
            None => Vec::new(),
        }
    }

    fn resume(&self, event: Event) {
        if let Err(PushError::Closed(_)) | Err(PushError::Full(_)) = self.resumed.try_push(event) {
            crate::log_error!(
                "lookup",
                "{}: an event could not be resumed and was lost",
                self.spec.name
            );
        }
    }

    /// Deliver answers. Never blocks; safe to call from async code.
    pub fn complete(&self, results: Vec<(LookupKey, LookupResult)>) {
        let now = Instant::now();
        for (key, result) in results {
            match &result {
                LookupResult::Found { value, ttl } => {
                    self.cache
                        .insert(key.clone(), Some(value.clone()), *ttl, now)
                }
                LookupResult::NotFound { ttl } => self.cache.insert(key.clone(), None, *ttl, now),
                LookupResult::Failed(reason) => {
                    crate::log_debug!("lookup", "{}: {key} failed: {reason}", self.spec.name)
                }
                LookupResult::Skipped => {}
            }
            // Hold the parking lock while resuming, so the `max_parked`
            // admission check in `process` sees a consistent total.
            let mut parking = self.lock();
            for mut event in self.release(&mut parking, &key) {
                match &result {
                    LookupResult::Found { value, .. } => {
                        self.stats.resolved.fetch_add(1, Ordering::Relaxed);
                        self.answer(&mut event, Some(value));
                    }
                    LookupResult::NotFound { .. } => {
                        self.stats.resolved.fetch_add(1, Ordering::Relaxed);
                        self.answer(&mut event, None);
                    }
                    LookupResult::Failed(_) => {
                        self.stats.failed.fetch_add(1, Ordering::Relaxed);
                        self.mark(&mut event, LookupStatus::Failed);
                    }
                    LookupResult::Skipped => {
                        self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
                        self.mark(&mut event, LookupStatus::Bypassed);
                    }
                }
                self.resume(event);
            }
        }
    }

    /// Release every event parked for longer than the deadline, as
    /// `timeout`. Cheap to call often; [`SegmentedPipeline`] calls it while
    /// draining.
    pub fn expire(&self, now: Instant) {
        let deadline = self.spec.deadline;
        let mut parking = self.lock();
        if parking.count == 0 {
            return;
        }
        let mut expired = Vec::new();
        parking.by_key.retain(|_, waiting| {
            let mut index = 0;
            while index < waiting.len() {
                if now.duration_since(waiting[index].1) >= deadline {
                    expired.push(waiting.swap_remove(index).0);
                } else {
                    index += 1;
                }
            }
            !waiting.is_empty()
        });
        parking.count -= expired.len();
        for mut event in expired {
            self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
            self.mark(&mut event, LookupStatus::Timeout);
            self.resume(event);
        }
    }

    /// Take up to `max` resumed events without blocking.
    pub fn pop_resumed(&self, max: usize) -> Vec<Event> {
        self.resumed.try_pop_batch(max)
    }

    /// Stop the point: requests are no longer accepted, and every parked
    /// event is released as `bypassed` (so shutting down loses nothing).
    pub fn shutdown(&self) {
        self.requests.close();
        let mut parking = self.lock();
        let keys: Vec<LookupKey> = parking.by_key.keys().cloned().collect();
        for key in keys {
            for mut event in self.release(&mut parking, &key) {
                self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
                self.mark(&mut event, LookupStatus::Bypassed);
                self.resume(event);
            }
        }
    }
}

/// What happened to an event in a [`SegmentedPipeline`].
#[derive(Debug)]
pub enum Outcome {
    /// The event went through every segment (or a stage dropped or failed it).
    Done(ProcessResult),
    /// The event is waiting at a lookup point; it comes back through
    /// [`SegmentedPipeline::drain_resumed`].
    Parked,
}

/// [`Pipeline`] segments separated by [`LookupPoint`]s:
/// `segment 0 → point 0 → segment 1 → point 1 → …`.
///
/// Like [`Pipeline`], one instance per worker thread; the lookup points are
/// shared between them.
pub struct SegmentedPipeline {
    segments: Vec<Pipeline>,
    points: Vec<Arc<LookupPoint>>,
    last_sweep: Instant,
}

/// How often [`SegmentedPipeline::drain_resumed`] checks deadlines.
const SWEEP_EVERY: Duration = Duration::from_millis(50);

impl SegmentedPipeline {
    /// A pipeline with one segment and no lookup points.
    pub fn new(first: Pipeline) -> Self {
        Self {
            segments: vec![first],
            points: Vec::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Append a lookup point followed by another segment.
    pub fn then_lookup(mut self, point: Arc<LookupPoint>, next: Pipeline) -> Self {
        self.points.push(point);
        self.segments.push(next);
        self
    }

    /// The lookup points, in order.
    pub fn points(&self) -> &[Arc<LookupPoint>] {
        &self.points
    }

    /// The segments, in order.
    pub fn segments(&self) -> &[Pipeline] {
        &self.segments
    }

    /// Run a new event from the first segment.
    pub fn run(&mut self, event: Event) -> Outcome {
        self.run_from(0, event)
    }

    fn run_from(&mut self, mut segment: usize, mut event: Event) -> Outcome {
        loop {
            match self.segments[segment].run(event) {
                ProcessResult::Continue(next) => match self.points.get(segment) {
                    None => return Outcome::Done(ProcessResult::Continue(next)),
                    Some(point) => match point.process(next) {
                        Step::Continue(next) => {
                            event = next;
                            segment += 1;
                        }
                        Step::Parked => return Outcome::Parked,
                    },
                },
                other => return Outcome::Done(other),
            }
        }
    }

    /// Release timed-out events, then continue up to `max` resumed events
    /// per lookup point through the rest of the pipeline. Call it from every
    /// batch and from [`crate::processing::workers::Worker::idle`].
    pub fn drain_resumed(&mut self, max: usize) -> Vec<ProcessResult> {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) >= SWEEP_EVERY {
            self.last_sweep = now;
            for point in &self.points {
                point.expire(now);
            }
        }
        let mut done = Vec::new();
        for index in 0..self.points.len() {
            for event in self.points[index].pop_resumed(max) {
                if let Outcome::Done(result) = self.run_from(index + 1, event) {
                    done.push(result);
                }
            }
        }
        done
    }
}

/// The boxed future an [`AsyncLookup`] returns.
pub type LookupFuture = Pin<Box<dyn Future<Output = Vec<(LookupKey, LookupResult)>> + Send>>;

/// An external service that answers lookups: DNS, a REST API, a database.
///
/// Implemented by the host application with whatever async stack it uses.
/// A key missing from the returned `Vec` gets no answer; its events wait
/// until the deadline.
pub trait AsyncLookup: Send + Sync {
    /// The lookup's name; normally the same as its [`LookupSpec::name`].
    fn name(&self) -> &'static str;

    /// Rate, concurrency and privacy limits. Defaults to
    /// [`LookupPolicy::default`].
    fn policy(&self) -> LookupPolicy {
        LookupPolicy::default()
    }

    /// Resolve a batch of keys (at most [`LookupPolicy::max_batch`]).
    fn resolve_batch(&self, keys: Vec<LookupKey>) -> LookupFuture;
}

/// A token bucket for requests per second, plus an optional rolling
/// 24-hour quota.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetConfig {
    /// Sustained requests per second.
    pub per_second: f64,
    /// The most requests allowed in a burst.
    pub burst: u32,
    /// The most requests in any 24 hours, if limited.
    pub daily: Option<u64>,
}

/// Opens after `failures` consecutive failed batches; after `cooldown`, one
/// trial batch is let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Consecutive failed batches that open the breaker.
    pub failures: u32,
    /// How long the breaker stays open.
    pub cooldown: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failures: 5,
            cooldown: Duration::from_secs(30),
        }
    }
}

/// Limits a [`LookupDriver`] applies to one [`AsyncLookup`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LookupPolicy {
    /// The most keys per [`AsyncLookup::resolve_batch`] call.
    pub max_batch: usize,
    /// The most batches in flight at once.
    pub max_in_flight: usize,
    /// Rate budget, if limited. One token is one key.
    pub budget: Option<BudgetConfig>,
    /// Circuit breaker settings.
    pub breaker: BreakerConfig,
    /// Whether keys that are private, loopback or otherwise non-public IP
    /// addresses may be sent. Off by default, so internal addresses never
    /// reach an internet service.
    pub send_private_ips: bool,
}

impl Default for LookupPolicy {
    fn default() -> Self {
        Self {
            max_batch: 100,
            max_in_flight: 4,
            budget: None,
            breaker: BreakerConfig::default(),
            send_private_ips: false,
        }
    }
}

/// The state of a [`BudgetConfig`].
#[derive(Debug)]
pub struct Budget {
    config: BudgetConfig,
    tokens: f64,
    refilled: Instant,
    day_started: Instant,
    day_used: u64,
}

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

impl Budget {
    /// A full budget as of `now`.
    pub fn new(config: BudgetConfig, now: Instant) -> Self {
        Self {
            config,
            tokens: f64::from(config.burst),
            refilled: now,
            day_started: now,
            day_used: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * self.config.per_second).min(f64::from(self.config.burst));
        self.refilled = now;
        if now.saturating_duration_since(self.day_started) >= DAY {
            self.day_started = now;
            self.day_used = 0;
        }
    }

    /// How many of `wanted` keys may be sent now. Takes the tokens for them.
    pub fn take(&mut self, wanted: usize, now: Instant) -> usize {
        self.refill(now);
        let mut allowed = (self.tokens.floor() as usize).min(wanted);
        if let Some(daily) = self.config.daily {
            let left = daily.saturating_sub(self.day_used);
            allowed = allowed.min(usize::try_from(left).unwrap_or(usize::MAX));
        }
        self.tokens -= allowed as f64;
        self.day_used += allowed as u64;
        allowed
    }
}

/// The state of a [`BreakerConfig`].
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    /// A closed breaker.
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            failures: 0,
            open_until: None,
        }
    }

    /// Whether a batch may be sent now.
    pub fn allow(&self, now: Instant) -> bool {
        self.open_until.is_none_or(|until| now >= until)
    }

    /// Whether the breaker is open as of `now`.
    pub fn is_open(&self, now: Instant) -> bool {
        !self.allow(now)
    }

    /// Record a batch that worked.
    pub fn success(&mut self) {
        self.failures = 0;
        self.open_until = None;
    }

    /// Record a batch that failed.
    pub fn failure(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= self.config.failures.max(1) {
            self.open_until = Some(now + self.config.cooldown);
        }
    }
}

/// Whether `key` is an IP address that should not leave the network:
/// private, loopback, link-local, unspecified, CGNAT, documentation,
/// broadcast, or IPv6 unique-local. Keys that are not IPs return `false`.
pub fn is_non_public_ip(key: &str) -> bool {
    key.parse::<IpAddr>().is_ok_and(is_non_public_addr)
}

/// [`is_non_public_ip`] for an already parsed address: true for private,
/// loopback, link-local, unspecified, broadcast, multicast, CGNAT,
/// documentation and benchmark ranges, IPv6 ULA and link-local. IPv4-mapped
/// IPv6 addresses are judged by their IPv4 part.
pub fn is_non_public_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_non_public_addr(IpAddr::V4(v4));
            }
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first == 0x2001 && ip.segments()[1] == 0x0db8)
        }
    }
}

/// The runtime-agnostic half of driving one [`AsyncLookup`] for one
/// [`LookupPoint`]: batching, the private-IP filter, budget, breaker and the
/// in-flight limit. The host's async loop does the rest:
///
/// ```text
/// loop {
///     notified_or_tick().await;
///     while let Some(batch) = driver.next_batch(Instant::now()) {
///         let future = driver.lookup().resolve_batch(batch.keys);
///         spawn(async move { driver.finish(future.await) });
///     }
/// }
/// ```
pub struct LookupDriver {
    point: Arc<LookupPoint>,
    lookup: Arc<dyn AsyncLookup>,
    policy: LookupPolicy,
    state: Mutex<DriverState>,
    in_flight: AtomicUsize,
}

struct DriverState {
    budget: Option<Budget>,
    breaker: CircuitBreaker,
}

/// Keys to send in one [`AsyncLookup::resolve_batch`] call.
#[derive(Debug)]
pub struct Batch {
    /// The keys.
    pub keys: Vec<LookupKey>,
}

impl LookupDriver {
    /// A driver for `lookup`, feeding `point`.
    pub fn new(point: Arc<LookupPoint>, lookup: Arc<dyn AsyncLookup>) -> Self {
        let policy = lookup.policy();
        let now = Instant::now();
        Self {
            state: Mutex::new(DriverState {
                budget: policy.budget.map(|config| Budget::new(config, now)),
                breaker: CircuitBreaker::new(policy.breaker),
            }),
            point,
            lookup,
            policy,
            in_flight: AtomicUsize::new(0),
        }
    }

    /// The lookup point.
    pub fn point(&self) -> &Arc<LookupPoint> {
        &self.point
    }

    /// The lookup service.
    pub fn lookup(&self) -> &Arc<dyn AsyncLookup> {
        &self.lookup
    }

    /// Batches currently in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    fn lock(&self) -> MutexGuard<'_, DriverState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The next batch to send, or `None` when there is nothing to do or a
    /// limit (in flight, breaker, budget) says wait. Keys that may not be
    /// sent (non-public IPs) are completed as [`LookupResult::Skipped`]
    /// right away. Each `Some` must be followed by one [`LookupDriver::finish`].
    pub fn next_batch(&self, now: Instant) -> Option<Batch> {
        if self.in_flight() >= self.policy.max_in_flight.max(1) {
            return None;
        }
        let mut state = self.lock();
        if !state.breaker.allow(now) {
            return None;
        }
        loop {
            let mut want = self.policy.max_batch.max(1);
            if let Some(budget) = &mut state.budget {
                want = budget.take(want.min(self.point.pending_requests()), now);
                if want == 0 {
                    return None;
                }
            }
            let mut keys = self.point.take_requests(want);
            if keys.is_empty() {
                return None;
            }
            if !self.policy.send_private_ips {
                let (private, public): (Vec<_>, Vec<_>) =
                    keys.into_iter().partition(|key| is_non_public_ip(key));
                if !private.is_empty() {
                    self.point.complete(
                        private
                            .into_iter()
                            .map(|key| (key, LookupResult::Skipped))
                            .collect(),
                    );
                }
                keys = public;
            }
            if !keys.is_empty() {
                self.in_flight.fetch_add(1, Ordering::Relaxed);
                return Some(Batch { keys });
            }
        }
    }

    /// Deliver a batch's answers and record its outcome for the breaker. A
    /// batch counts as failed when every answer is [`LookupResult::Failed`].
    pub fn finish(&self, results: Vec<(LookupKey, LookupResult)>) {
        let failed = !results.is_empty()
            && results
                .iter()
                .all(|(_, r)| matches!(r, LookupResult::Failed(_)));
        {
            let mut state = self.lock();
            if failed {
                state.breaker.failure(Instant::now());
            } else {
                state.breaker.success();
            }
        }
        self.point.complete(results);
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Origin, RawData};
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Poll, Wake, Waker};

    fn event(ip: &str) -> Event {
        let mut event = Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_hostname("test"),
            RawData::from_text("line"),
        );
        event.add_field("source.ip".into(), FieldValue::Str(ip.into()));
        event
    }

    fn key(event: &Event) -> Option<LookupKey> {
        match event.get_field("source.ip") {
            Some(FieldValue::Str(ip)) => Some(ip.clone()),
            _ => None,
        }
    }

    fn apply(event: &mut Event, value: Option<&FieldValue>) {
        if let Some(value) = value {
            event.add_field("source.domain".into(), value.clone());
        }
    }

    fn status(event: &Event) -> &str {
        match event.get_field("enrichment.rdns.status") {
            Some(FieldValue::Str(s)) => s.as_str(),
            _ => "",
        }
    }

    fn point(spec: impl FnOnce(LookupSpec) -> LookupSpec) -> Arc<LookupPoint> {
        Arc::new(LookupPoint::new(spec(LookupSpec::new(
            "rdns", "test", key, apply,
        ))))
    }

    fn found(name: &str) -> LookupResult {
        LookupResult::found(FieldValue::Str(name.into()), Duration::from_secs(60))
    }

    fn continued(result: &ProcessResult) -> &Event {
        match result {
            ProcessResult::Continue(event) => event,
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    /// A minimal `block_on` for the tests: std only.
    fn block_on<F: Future>(future: F) -> F::Output {
        struct Unpark(std::thread::Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
            std::thread::park();
        }
    }

    struct FakeDns {
        calls: AtomicUsize,
        fail: AtomicBool,
    }

    impl AsyncLookup for FakeDns {
        fn name(&self) -> &'static str {
            "rdns"
        }
        fn policy(&self) -> LookupPolicy {
            LookupPolicy {
                max_batch: 10,
                breaker: BreakerConfig {
                    failures: 2,
                    cooldown: Duration::from_secs(3600),
                },
                ..LookupPolicy::default()
            }
        }
        fn resolve_batch(&self, keys: Vec<LookupKey>) -> LookupFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let fail = self.fail.load(Ordering::SeqCst);
            Box::pin(async move {
                keys.into_iter()
                    .map(|key| {
                        let result = if fail {
                            LookupResult::Failed("unreachable".into())
                        } else if key.ends_with(".9") {
                            LookupResult::not_found(Duration::from_secs(60))
                        } else {
                            found(&format!("host-{key}"))
                        };
                        (key, result)
                    })
                    .collect()
            })
        }
    }

    #[test]
    fn hit_miss_and_coalescing() {
        let rdns = point(|s| s);
        let notified = Arc::new(AtomicUsize::new(0));
        let n = notified.clone();
        rdns.set_notifier(move || {
            n.fetch_add(1, Ordering::SeqCst);
        });
        let mut pipeline =
            SegmentedPipeline::new(Pipeline::new()).then_lookup(rdns.clone(), Pipeline::new());

        // Three events, one key: one request, one notification.
        for _ in 0..3 {
            assert!(matches!(
                pipeline.run(event("203.0.113.5")),
                Outcome::Parked
            ));
        }
        assert_eq!(notified.load(Ordering::SeqCst), 1);
        assert_eq!(rdns.parked_len(), 3);
        let keys = rdns.take_requests(10);
        assert_eq!(keys, vec![Text::from("203.0.113.5")]);

        rdns.complete(vec![(keys[0].clone(), found("web.example"))]);
        let done = pipeline.drain_resumed(10);
        assert_eq!(done.len(), 3);
        for result in &done {
            let event = continued(result);
            assert_eq!(status(event), "ok");
            assert_eq!(
                event.get_field("source.domain"),
                Some(&FieldValue::Str("web.example".into()))
            );
            assert!(matches!(
                event.get_field("enrichment.rdns.at"),
                Some(FieldValue::Time(_))
            ));
        }

        // Now cached: no parking at all.
        match pipeline.run(event("203.0.113.5")) {
            Outcome::Done(result) => assert_eq!(status(continued(&result)), "ok"),
            Outcome::Parked => panic!("expected a cache hit"),
        }
        assert_eq!(rdns.stats().hits.load(Ordering::Relaxed), 1);
        assert_eq!(rdns.stats().requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn events_without_a_key_pass_untouched() {
        let rdns = point(|s| s);
        let mut pipeline =
            SegmentedPipeline::new(Pipeline::new()).then_lookup(rdns.clone(), Pipeline::new());
        let plain = Event::new(
            Timestamp::now(),
            Timestamp::now(),
            Origin::from_hostname("test"),
            RawData::from_text("no ip here"),
        );
        match pipeline.run(plain) {
            Outcome::Done(result) => assert_eq!(status(continued(&result)), ""),
            Outcome::Parked => panic!("no key, nothing to park"),
        }
    }

    #[test]
    fn negative_answers_are_cached_until_their_ttl() {
        let cache = LookupCache::new(10);
        let now = Instant::now();
        cache.insert("k".into(), None, Duration::from_secs(5), now);
        assert_eq!(cache.get("k", now), Cached::NotFound);
        assert_eq!(cache.get("k", now + Duration::from_secs(6)), Cached::Miss);
    }

    #[test]
    fn cache_evicts_when_full() {
        let cache = LookupCache::new(4);
        let now = Instant::now();
        for n in 0..4u64 {
            cache.insert(n.to_string().into(), None, Duration::from_secs(10 + n), now);
        }
        cache.insert("new".into(), None, Duration::from_secs(60), now);
        assert!(cache.len() <= 4);
        assert_eq!(cache.get("new", now), Cached::NotFound);
        assert_eq!(
            cache.get("3", now),
            Cached::NotFound,
            "the longest-lived entry is kept"
        );
    }

    #[test]
    fn deadline_releases_events_as_timeout() {
        let rdns = point(|s| s.with_deadline(Duration::ZERO));
        let mut pipeline =
            SegmentedPipeline::new(Pipeline::new()).then_lookup(rdns.clone(), Pipeline::new());
        assert!(matches!(
            pipeline.run(event("203.0.113.5")),
            Outcome::Parked
        ));
        rdns.expire(Instant::now());
        let done = pipeline.drain_resumed(10);
        assert_eq!(done.len(), 1);
        assert_eq!(status(continued(&done[0])), "timeout");
        assert_eq!(rdns.parked_len(), 0);
        // A late answer still fills the cache, and resumes nothing.
        rdns.complete(vec![("203.0.113.5".into(), found("late"))]);
        assert!(pipeline.drain_resumed(10).is_empty());
        assert!(matches!(
            pipeline.run(event("203.0.113.5")),
            Outcome::Done(_)
        ));
    }

    #[test]
    fn a_full_parking_lot_bypasses() {
        let rdns = point(|s| s.with_max_parked(2));
        assert!(matches!(rdns.process(event("203.0.113.1")), Step::Parked));
        assert!(matches!(rdns.process(event("203.0.113.2")), Step::Parked));
        match rdns.process(event("203.0.113.3")) {
            Step::Continue(event) => assert_eq!(status(&event), "bypassed"),
            Step::Parked => panic!("the parking lot is full"),
        }
        assert_eq!(rdns.take_requests(10).len(), 2);
        // Resumed-but-not-drained events still count against the limit.
        rdns.complete(vec![("203.0.113.1".into(), found("a"))]);
        assert!(matches!(
            rdns.process(event("203.0.113.4")),
            Step::Continue(_)
        ));
        assert_eq!(rdns.pop_resumed(10).len(), 1);
        assert!(matches!(rdns.process(event("203.0.113.4")), Step::Parked));
    }

    #[test]
    fn failures_and_shutdown_resume_everything() {
        let rdns = point(|s| s);
        assert!(matches!(rdns.process(event("203.0.113.1")), Step::Parked));
        assert!(matches!(rdns.process(event("203.0.113.2")), Step::Parked));
        rdns.complete(vec![(
            "203.0.113.1".into(),
            LookupResult::Failed("boom".into()),
        )]);
        rdns.shutdown();
        let mut statuses: Vec<String> = rdns
            .pop_resumed(10)
            .iter()
            .map(|e| status(e).to_string())
            .collect();
        statuses.sort();
        assert_eq!(statuses, ["bypassed", "failed"]);
        // A failure is not cached; after shutdown misses bypass.
        match rdns.process(event("203.0.113.1")) {
            Step::Continue(event) => assert_eq!(status(&event), "bypassed"),
            Step::Parked => panic!("shut down"),
        }
    }

    #[test]
    fn resumed_events_continue_in_the_next_segment() {
        fn tag(mut event: Event) -> ProcessResult {
            event.add_field("seg_b".into(), FieldValue::Bool(true));
            ProcessResult::Continue(event)
        }
        let rdns = point(|s| s);
        let mut b = Pipeline::new();
        b.add_stage(crate::processing::pipeline::Processor::new(
            "tag", "tag", tag,
        ));
        let mut pipeline = SegmentedPipeline::new(Pipeline::new()).then_lookup(rdns.clone(), b);
        assert!(matches!(
            pipeline.run(event("203.0.113.1")),
            Outcome::Parked
        ));
        assert!(matches!(
            pipeline.run(event("203.0.113.2")),
            Outcome::Parked
        ));
        // Answers in reverse order: completion order wins.
        rdns.complete(vec![("203.0.113.2".into(), found("two"))]);
        rdns.complete(vec![("203.0.113.1".into(), found("one"))]);
        let done = pipeline.drain_resumed(10);
        let names: Vec<_> = done
            .iter()
            .map(|r| {
                let e = continued(r);
                assert_eq!(e.get_field("seg_b"), Some(&FieldValue::Bool(true)));
                e.get_field("source.domain").cloned()
            })
            .collect();
        assert_eq!(
            names,
            [
                Some(FieldValue::Str("two".into())),
                Some(FieldValue::Str("one".into()))
            ]
        );
    }

    #[test]
    fn driver_filters_private_ips_and_opens_the_breaker() {
        let rdns = point(|s| s);
        let dns = Arc::new(FakeDns {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        });
        let driver = LookupDriver::new(rdns.clone(), dns.clone());

        for ip in ["10.0.0.1", "8.8.8.9", "1.1.1.1"] {
            assert!(matches!(rdns.process(event(ip)), Step::Parked));
        }
        let batch = driver
            .next_batch(Instant::now())
            .expect("public keys to send");
        assert_eq!(batch.keys.len(), 2);
        assert_eq!(driver.in_flight(), 1);
        // The private key never left: it resumed as bypassed already.
        let early = rdns.pop_resumed(10);
        assert_eq!(early.len(), 1);
        assert_eq!(status(&early[0]), "bypassed");

        driver.finish(block_on(dns.resolve_batch(batch.keys)));
        assert_eq!(driver.in_flight(), 0);
        let mut statuses: Vec<String> = rdns
            .pop_resumed(10)
            .iter()
            .map(|e| status(e).to_string())
            .collect();
        statuses.sort();
        assert_eq!(statuses, ["not_found", "ok"]);

        // Two failed batches open the breaker.
        dns.fail.store(true, Ordering::SeqCst);
        for ip in ["9.9.9.20", "9.9.9.21"] {
            assert!(matches!(rdns.process(event(ip)), Step::Parked));
            let batch = driver.next_batch(Instant::now()).unwrap();
            driver.finish(block_on(dns.resolve_batch(batch.keys)));
        }
        assert!(matches!(rdns.process(event("9.9.9.22")), Step::Parked));
        assert!(
            driver.next_batch(Instant::now()).is_none(),
            "breaker is open"
        );
        assert_eq!(dns.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn budget_limits_rate_and_daily_quota() {
        let start = Instant::now();
        let mut budget = Budget::new(
            BudgetConfig {
                per_second: 2.0,
                burst: 4,
                daily: Some(7),
            },
            start,
        );
        assert_eq!(budget.take(10, start), 4);
        assert_eq!(budget.take(10, start), 0);
        assert_eq!(budget.take(10, start + Duration::from_secs(1)), 2);
        assert_eq!(
            budget.take(10, start + Duration::from_secs(10)),
            1,
            "daily quota"
        );
        assert_eq!(budget.take(10, start + DAY + Duration::from_secs(10)), 4);
    }

    #[test]
    fn non_public_ips() {
        for ip in [
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "192.0.2.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_non_public_ip(ip), "{ip}");
        }
        for key in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700::1111",
            "example.com",
            "abc",
        ] {
            assert!(!is_non_public_ip(key), "{key}");
        }
    }
}
