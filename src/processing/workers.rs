//! A std-only runtime for synchronous event processing: a bounded queue and
//! a pool of worker threads that drain it in batches.
//!
//! # Design
//!
//! uSIEM processes events synchronously, on OS threads; async I/O belongs
//! to the host application (see the [`crate::processing`] module docs). The
//! two meet at a [`Queue`]:
//!
//! - Async producers (a tokio socket loop, say) call [`Queue::try_push`],
//!   which never blocks. On [`PushError::Full`] the producer decides what to
//!   do: drop the item and count it ([`Queue::push_or_drop`]), or wait
//!   asynchronously and retry, which pushes back on its own sender.
//! - Sync producers can use [`Queue::push`] or [`Queue::push_timeout`].
//! - Consumers take whole batches with [`Queue::pop_batch`]. It waits for a
//!   first item, then lingers briefly to fill the batch, so a quiet source
//!   doesn't add latency and a busy one gets large batches.
//!
//! A [`WorkerPool`] runs `n` threads over one queue. Each thread owns its own
//! [`Worker`], built by a factory, so per-thread state (a parser, a
//! [`crate::processing::pipeline::Pipeline`], a storage writer) needs no
//! lock. A worker that panics loses the batch it was processing; the pool
//! logs it, counts it in [`PoolStats`] and builds a fresh worker in its place.
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! use usiem::processing::workers::{PoolConfig, Queue, Worker, WorkerPool};
//!
//! struct Summer(Arc<Mutex<u64>>);
//! impl Worker<u64> for Summer {
//!     fn process(&mut self, batch: Vec<u64>) {
//!         *self.0.lock().unwrap() += batch.iter().sum::<u64>();
//!     }
//! }
//!
//! let total = Arc::new(Mutex::new(0));
//! let queue = Arc::new(Queue::new(1024));
//! let shared = total.clone();
//! let pool = WorkerPool::start("sum", 2, queue.clone(), PoolConfig::default(), move |_| {
//!     Summer(shared.clone())
//! })
//! .unwrap();
//! for n in 1..=100 {
//!     queue.push(n).unwrap();
//! }
//! pool.shutdown(); // closes the queue, drains it, joins the threads
//! assert_eq!(*total.lock().unwrap(), 5050);
//! ```

use crate::event::field::Timestamp;
use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Why an item could not be pushed. The item is handed back.
pub enum PushError<T> {
    /// The queue is at capacity.
    Full(T),
    /// The queue was closed; nothing more will be accepted.
    Closed(T),
}

impl<T> PushError<T> {
    /// The item that could not be pushed.
    pub fn into_inner(self) -> T {
        match self {
            PushError::Full(item) | PushError::Closed(item) => item,
        }
    }

    /// Whether the queue was full (as opposed to closed).
    pub fn is_full(&self) -> bool {
        matches!(self, PushError::Full(_))
    }
}

impl<T> fmt::Debug for PushError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushError::Full(_) => f.write_str("Full(..)"),
            PushError::Closed(_) => f.write_str("Closed(..)"),
        }
    }
}

impl<T> fmt::Display for PushError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushError::Full(_) => f.write_str("queue is full"),
            PushError::Closed(_) => f.write_str("queue is closed"),
        }
    }
}

impl<T> std::error::Error for PushError<T> {}

/// What [`Queue::pop_batch`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Pop<T> {
    /// One or more items, at most the requested maximum.
    Batch(Vec<T>),
    /// Nothing arrived within the idle timeout.
    Idle,
    /// The queue is closed and fully drained.
    Closed,
}

struct State<T> {
    items: VecDeque<T>,
    closed: bool,
}

/// A bounded multi-producer, multi-consumer FIFO queue.
///
/// Built on `Mutex` + `Condvar` only. Share it with `Arc`.
pub struct Queue<T> {
    state: Mutex<State<T>>,
    not_empty: Condvar,
    not_full: Condvar,
    capacity: usize,
    dropped: AtomicU64,
}

impl<T> Queue<T> {
    /// A queue holding at most `capacity` items (minimum 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            state: Mutex::new(State {
                items: VecDeque::with_capacity(capacity.min(4096)),
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // A panic while holding this lock can't leave the VecDeque in a
        // broken state (every critical section is a single push/drain), so
        // a poisoned lock is safe to keep using.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Push without blocking. Safe to call from async code.
    pub fn try_push(&self, item: T) -> Result<(), PushError<T>> {
        let mut state = self.lock();
        if state.closed {
            return Err(PushError::Closed(item));
        }
        if state.items.len() >= self.capacity {
            return Err(PushError::Full(item));
        }
        state.items.push_back(item);
        drop(state);
        self.not_empty.notify_one();
        Ok(())
    }

    /// Push without blocking; when the queue is full or closed, discard the
    /// item and count it in [`Queue::dropped`]. Returns whether it was queued.
    pub fn push_or_drop(&self, item: T) -> bool {
        match self.try_push(item) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Push, blocking until there is room or the queue is closed. Never call
    /// this from an async task.
    pub fn push(&self, item: T) -> Result<(), PushError<T>> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return Err(PushError::Closed(item));
            }
            if state.items.len() < self.capacity {
                state.items.push_back(item);
                drop(state);
                self.not_empty.notify_one();
                return Ok(());
            }
            state = self.not_full.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Push, blocking for at most `timeout`. Never call this from an async task.
    pub fn push_timeout(&self, item: T, timeout: Duration) -> Result<(), PushError<T>> {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            if state.closed {
                return Err(PushError::Closed(item));
            }
            if state.items.len() < self.capacity {
                state.items.push_back(item);
                drop(state);
                self.not_empty.notify_one();
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PushError::Full(item));
            }
            state = self
                .not_full
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Take up to `max` items.
    ///
    /// Waits up to `idle` for a first item (returning [`Pop::Idle`] if none
    /// comes), then keeps collecting until the batch holds `max` items or
    /// `linger` has passed since the first one. Returns [`Pop::Closed`] only
    /// once the queue is closed *and* empty, so closing drains everything.
    pub fn pop_batch(&self, max: usize, linger: Duration, idle: Duration) -> Pop<T> {
        let max = max.max(1);
        let mut state = self.lock();
        let idle_deadline = Instant::now() + idle;
        while state.items.is_empty() {
            if state.closed {
                return Pop::Closed;
            }
            let now = Instant::now();
            if now >= idle_deadline {
                return Pop::Idle;
            }
            state = self
                .not_empty
                .wait_timeout(state, idle_deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }

        let mut batch = Vec::with_capacity(max.min(state.items.len().max(16)));
        let linger_deadline = Instant::now() + linger;
        loop {
            let take = (max - batch.len()).min(state.items.len());
            batch.extend(state.items.drain(..take));
            if take > 0 {
                // Room was freed: wake blocked producers.
                self.not_full.notify_all();
            }
            if batch.len() >= max || state.closed {
                break;
            }
            let now = Instant::now();
            if now >= linger_deadline {
                break;
            }
            state = self
                .not_empty
                .wait_timeout(state, linger_deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        Pop::Batch(batch)
    }

    /// Take up to `max` items without waiting. Safe to call from async code;
    /// returns an empty `Vec` when nothing is queued.
    pub fn try_pop_batch(&self, max: usize) -> Vec<T> {
        let mut state = self.lock();
        let take = max.min(state.items.len());
        let batch: Vec<T> = state.items.drain(..take).collect();
        drop(state);
        if take > 0 {
            self.not_full.notify_all();
        }
        batch
    }

    /// Stop accepting items. Consumers still drain what is queued, then see
    /// [`Pop::Closed`]; blocked producers get [`PushError::Closed`].
    pub fn close(&self) {
        self.lock().closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    /// Whether [`Queue::close`] has been called.
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Items currently queued.
    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    /// Whether the queue is currently empty.
    pub fn is_empty(&self) -> bool {
        self.lock().items.is_empty()
    }

    /// The maximum number of queued items.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Add `n` to [`Queue::dropped`], for producers that handle a failed
    /// [`Queue::try_push`] themselves and gave up on the item.
    pub fn count_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Items discarded so far, by [`Queue::push_or_drop`] or reported
    /// through [`Queue::count_dropped`].
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// One thread's processing logic in a [`WorkerPool`].
///
/// Each pool thread owns its own `Worker`, so `&mut self` state needs no lock.
pub trait Worker<I>: Send {
    /// Process one batch, in queue order.
    fn process(&mut self, batch: Vec<I>);

    /// Called when no item arrived within [`PoolConfig::idle`]. Use it for
    /// periodic work: flushes, retention, metrics.
    fn idle(&mut self, _now: Timestamp) {}

    /// Called once when the queue is closed and drained, before the thread
    /// exits.
    fn finish(&mut self) {}
}

/// Batching parameters for a [`WorkerPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// Maximum items per batch.
    pub batch: usize,
    /// How long to keep filling a batch after its first item.
    pub linger: Duration,
    /// How long to wait for a first item before calling [`Worker::idle`].
    pub idle: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            batch: 1000,
            linger: Duration::from_millis(200),
            idle: Duration::from_secs(1),
        }
    }
}

/// Counters shared by every thread of a [`WorkerPool`].
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Items handed to [`Worker::process`] (including batches that panicked).
    pub items: AtomicU64,
    /// Batches handed to [`Worker::process`].
    pub batches: AtomicU64,
    /// Batches whose processing panicked; their items were lost.
    pub panics: AtomicU64,
}

/// A fixed set of named threads draining one [`Queue`].
pub struct WorkerPool<I> {
    name: String,
    queue: Arc<Queue<I>>,
    stats: Arc<PoolStats>,
    handles: Vec<JoinHandle<()>>,
}

impl<I: Send + 'static> WorkerPool<I> {
    /// Start `threads` threads (minimum 1) named `{name}-{i}`, each running
    /// the worker that `factory(i)` builds. The factory is called again to
    /// replace a worker that panicked.
    pub fn start<W, F>(
        name: &str,
        threads: usize,
        queue: Arc<Queue<I>>,
        config: PoolConfig,
        factory: F,
    ) -> std::io::Result<Self>
    where
        W: Worker<I> + 'static,
        F: Fn(usize) -> W + Send + Sync + 'static,
    {
        let factory = Arc::new(factory);
        let stats = Arc::new(PoolStats::default());
        let mut pool = Self {
            name: name.to_string(),
            queue,
            stats,
            handles: Vec::new(),
        };
        for index in 0..threads.max(1) {
            let queue = pool.queue.clone();
            let stats = pool.stats.clone();
            let factory = factory.clone();
            let thread_name = format!("{name}-{index}");
            let spawned = std::thread::Builder::new()
                .name(thread_name.clone())
                .spawn(move || run_worker(&thread_name, index, &queue, config, &stats, &*factory));
            match spawned {
                Ok(handle) => pool.handles.push(handle),
                Err(e) => {
                    // Dropping the pool closes the queue and joins what started.
                    return Err(e);
                }
            }
        }
        Ok(pool)
    }
}

impl<I> WorkerPool<I> {
    /// The pool's name, as given to [`WorkerPool::start`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The queue this pool drains.
    pub fn queue(&self) -> &Arc<Queue<I>> {
        &self.queue
    }

    /// The pool's counters.
    pub fn stats(&self) -> &Arc<PoolStats> {
        &self.stats
    }

    /// Number of threads.
    pub fn threads(&self) -> usize {
        self.handles.len()
    }

    /// Close the queue, let the workers drain it, and join every thread.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.queue.close();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                crate::log_error!("workers", "a thread of pool '{}' panicked", self.name);
            }
        }
    }
}

impl<I> Drop for WorkerPool<I> {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_worker<I, W, F>(
    thread: &str,
    index: usize,
    queue: &Queue<I>,
    config: PoolConfig,
    stats: &PoolStats,
    factory: &F,
) where
    W: Worker<I>,
    F: Fn(usize) -> W,
{
    let mut worker = factory(index);
    loop {
        match queue.pop_batch(config.batch, config.linger, config.idle) {
            Pop::Batch(batch) => {
                let len = batch.len() as u64;
                stats.items.fetch_add(len, Ordering::Relaxed);
                stats.batches.fetch_add(1, Ordering::Relaxed);
                if catch_unwind(AssertUnwindSafe(|| worker.process(batch))).is_err() {
                    stats.panics.fetch_add(1, Ordering::Relaxed);
                    crate::log_error!(
                        "workers",
                        "{thread}: a batch of {len} items panicked; restarting the worker"
                    );
                    worker = factory(index);
                }
            }
            Pop::Idle => {
                if catch_unwind(AssertUnwindSafe(|| worker.idle(Timestamp::now()))).is_err() {
                    stats.panics.fetch_add(1, Ordering::Relaxed);
                    crate::log_error!(
                        "workers",
                        "{thread}: idle work panicked; restarting the worker"
                    );
                    worker = factory(index);
                }
            }
            Pop::Closed => break,
        }
    }
    worker.finish();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const SHORT: Duration = Duration::from_millis(20);

    #[test]
    fn try_push_reports_full_and_closed() {
        let queue = Queue::new(2);
        assert!(queue.try_push(1).is_ok());
        assert!(queue.try_push(2).is_ok());
        let err = queue.try_push(3).unwrap_err();
        assert!(err.is_full());
        assert_eq!(err.into_inner(), 3);
        assert!(!queue.push_or_drop(4));
        assert_eq!(queue.dropped(), 1);
        queue.close();
        assert!(matches!(queue.try_push(5), Err(PushError::Closed(5))));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn pop_batch_respects_max_and_order() {
        let queue = Queue::new(100);
        for n in 0..10 {
            queue.try_push(n).unwrap();
        }
        assert_eq!(
            queue.pop_batch(4, SHORT, SHORT),
            Pop::Batch(vec![0, 1, 2, 3])
        );
        assert_eq!(
            queue.pop_batch(100, SHORT, SHORT),
            Pop::Batch((4..10).collect())
        );
        assert_eq!(queue.pop_batch(100, SHORT, SHORT), Pop::Idle);
    }

    #[test]
    fn pop_batch_lingers_for_late_items() {
        let queue = Arc::new(Queue::new(100));
        queue.try_push(0).unwrap();
        let producer = queue.clone();
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            producer.try_push(1).unwrap();
        });
        let batch = queue.pop_batch(2, Duration::from_secs(5), SHORT);
        late.join().unwrap();
        // Returns as soon as the batch is full, long before the linger ends.
        assert_eq!(batch, Pop::Batch(vec![0, 1]));
    }

    #[test]
    fn pop_batch_stops_lingering_at_the_deadline() {
        let queue = Queue::new(100);
        queue.try_push(7).unwrap();
        let started = Instant::now();
        assert_eq!(queue.pop_batch(10, SHORT, SHORT), Pop::Batch(vec![7]));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn close_drains_before_reporting_closed() {
        let queue = Queue::new(10);
        queue.try_push(1).unwrap();
        queue.close();
        assert_eq!(queue.pop_batch(10, SHORT, SHORT), Pop::Batch(vec![1]));
        assert_eq!(queue.pop_batch(10, SHORT, SHORT), Pop::Closed);
    }

    #[test]
    fn blocking_push_waits_for_room_and_wakes_on_close() {
        let queue = Arc::new(Queue::new(1));
        queue.try_push(0).unwrap();
        let producer = queue.clone();
        let blocked = std::thread::spawn(move || producer.push(1));
        std::thread::sleep(SHORT);
        assert_eq!(queue.pop_batch(1, SHORT, SHORT), Pop::Batch(vec![0]));
        assert!(blocked.join().unwrap().is_ok());

        assert!(queue.push_timeout(2, SHORT).unwrap_err().is_full());
        let producer = queue.clone();
        let blocked = std::thread::spawn(move || producer.push(3));
        std::thread::sleep(SHORT);
        queue.close();
        assert!(matches!(blocked.join().unwrap(), Err(PushError::Closed(3))));
    }

    struct Collect {
        seen: Arc<Mutex<Vec<u32>>>,
        finished: Arc<AtomicUsize>,
    }

    impl Worker<u32> for Collect {
        fn process(&mut self, batch: Vec<u32>) {
            self.seen.lock().unwrap().extend(batch);
        }
        fn finish(&mut self) {
            self.finished.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn many_producers_many_workers_lose_nothing() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let finished = Arc::new(AtomicUsize::new(0));
        let queue = Arc::new(Queue::new(64));
        let (s, f) = (seen.clone(), finished.clone());
        let config = PoolConfig {
            batch: 16,
            linger: Duration::from_millis(1),
            idle: SHORT,
        };
        let pool = WorkerPool::start("collect", 4, queue.clone(), config, move |_| Collect {
            seen: s.clone(),
            finished: f.clone(),
        })
        .unwrap();
        assert_eq!(pool.threads(), 4);

        let producers: Vec<_> = (0..4u32)
            .map(|p| {
                let queue = queue.clone();
                std::thread::spawn(move || {
                    for n in 0..1000 {
                        queue.push(p * 1000 + n).unwrap();
                    }
                })
            })
            .collect();
        for producer in producers {
            producer.join().unwrap();
        }
        let stats = pool.stats().clone();
        pool.shutdown();

        let mut seen = seen.lock().unwrap().clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..4000).collect::<Vec<_>>());
        assert_eq!(stats.items.load(Ordering::Relaxed), 4000);
        assert_eq!(finished.load(Ordering::SeqCst), 4);
    }

    struct Fragile {
        seen: Arc<Mutex<Vec<u32>>>,
        idles: Arc<AtomicUsize>,
    }

    impl Worker<u32> for Fragile {
        fn process(&mut self, batch: Vec<u32>) {
            if batch.contains(&13) {
                panic!("unlucky batch");
            }
            self.seen.lock().unwrap().extend(batch);
        }
        fn idle(&mut self, _now: Timestamp) {
            self.idles.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_panicking_worker_is_replaced_and_idle_runs() {
        let built = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let idles = Arc::new(AtomicUsize::new(0));
        let queue = Arc::new(Queue::new(16));
        let (b, s, i) = (built.clone(), seen.clone(), idles.clone());
        let config = PoolConfig {
            batch: 1,
            linger: Duration::ZERO,
            idle: Duration::from_millis(5),
        };
        let pool = WorkerPool::start("fragile", 1, queue.clone(), config, move |_| {
            b.fetch_add(1, Ordering::SeqCst);
            Fragile {
                seen: s.clone(),
                idles: i.clone(),
            }
        })
        .unwrap();
        for n in [12, 13, 14] {
            queue.push(n).unwrap();
        }
        let started = Instant::now();
        while idles.load(Ordering::SeqCst) == 0 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stats = pool.stats().clone();
        pool.shutdown();

        assert_eq!(*seen.lock().unwrap(), vec![12, 14]);
        assert_eq!(stats.panics.load(Ordering::Relaxed), 1);
        assert_eq!(built.load(Ordering::SeqCst), 2);
        assert!(idles.load(Ordering::SeqCst) >= 1);
    }
}
