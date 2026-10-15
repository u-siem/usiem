//! [`InvocationContext`]: who is calling, and on whose behalf — threaded
//! through every [`crate::processing::action::Action::execute`] call.
//!
//! Authorization ([`crate::security`]), multi-tenant scoping, and audit
//! trails all need to know *who* is asking before they can do anything
//! useful, so this context is a required parameter rather than an
//! afterthought bolted on later. It carries no transport or protocol
//! concerns (no HTTP headers, no JSON-RPC request id shape) — an MCP
//! transport crate, a CLI, or in-process application code all construct one
//! the same way.

use crate::event::field::Text;
use crate::security::Principal;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A tenant identifier for multi-tenant (MSSP) deployments. An opaque
/// string, the same convention as
/// [`crate::processing::action::ActionDescriptor::name`] capability names —
/// this crate does not define tenant structure or a tenant directory.
pub type TenantId = Text;

/// Who is calling, and the request-scoped metadata that travels with the
/// call: which tenant it's scoped to, whether it's an agent acting for a
/// human, why it's being made (for audit), and a cooperative cancellation
/// flag.
///
/// Deliberately synchronous-friendly: cancellation is a plain
/// [`AtomicBool`] flag an [`crate::processing::action::Action`] may poll
/// during long-running work, not an `async` `Future`/runtime dependency —
/// this crate takes on no async runtime, per its "as few external crates as
/// possible" stance. A transport built on an async runtime can still honor
/// it (e.g. a task that flips the flag when its underlying request is
/// cancelled).
#[derive(Clone)]
pub struct InvocationContext {
    pub principal: Principal,
    pub tenant: Option<TenantId>,
    pub request_id: Text,
    /// Set when an agent/service principal is acting on behalf of a human —
    /// e.g. an MCP-driven AI calling with its own service identity as
    /// [`InvocationContext::principal`], but attributing the request to the
    /// analyst who asked it to. Purely informational for audit; it does not
    /// change which permissions apply — those are still checked against
    /// `principal`.
    pub on_behalf_of: Option<Principal>,
    /// A human-readable justification for this call (e.g. an analyst's
    /// stated reason for firing a destructive action), carried through to
    /// the audit event.
    pub reason: Option<Text>,
    cancel: Arc<AtomicBool>,
}

impl InvocationContext {
    /// A new context for `principal`, with a freshly generated
    /// [`InvocationContext::request_id`] and nothing else set.
    pub fn new(principal: Principal) -> Self {
        Self {
            principal,
            tenant: None,
            request_id: Text::from(uuid_like()),
            on_behalf_of: None,
            reason: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_tenant(mut self, tenant: impl Into<TenantId>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<Text>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn on_behalf_of(mut self, principal: Principal) -> Self {
        self.on_behalf_of = Some(principal);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<Text>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// A cancellation handle that can be flipped from another thread while
    /// this context is in flight inside a long-running
    /// [`crate::processing::action::Action::execute`] call.
    pub fn cancellation_handle(&self) -> CancellationHandle {
        CancellationHandle {
            flag: self.cancel.clone(),
        }
    }

    /// Whether cancellation has been requested. An [`Action`](crate::processing::action::Action)
    /// implementation doing long-running work should poll this
    /// periodically; nothing enforces that it does.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// A cheaply-cloneable handle that can request cancellation of the
/// [`InvocationContext`] it was obtained from.
#[derive(Clone)]
pub struct CancellationHandle {
    flag: Arc<AtomicBool>,
}

impl CancellationHandle {
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// A dependency-free, good-enough-for-correlation request id: not a real
/// UUID (no `uuid` crate — this crate's "as few external crates as
/// possible" stance), just process-unique-enough to tie an audit event back
/// to the call that produced it. Callers who need a real UUID (e.g. to
/// match an MCP transport's own request id) should set one explicitly via
/// [`InvocationContext::with_request_id`].
fn uuid_like() -> String {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = crate::event::field::Timestamp::now().as_nanos();
    format!("req-{nanos:x}-{n:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::PrincipalKind;

    #[test]
    fn test_new_context_generates_unique_request_ids() {
        let a = InvocationContext::new(Principal::new("a", PrincipalKind::User));
        let b = InvocationContext::new(Principal::new("a", PrincipalKind::User));
        assert_ne!(a.request_id, b.request_id);
    }

    #[test]
    fn test_builder_methods_set_fields() {
        let ctx = InvocationContext::new(Principal::new("svc", PrincipalKind::Service))
            .with_tenant("acme")
            .with_request_id("req-123")
            .with_reason("analyst requested containment");
        assert_eq!(ctx.tenant.as_deref(), Some("acme"));
        assert_eq!(ctx.request_id, "req-123");
        assert_eq!(ctx.reason.as_deref(), Some("analyst requested containment"));
    }

    #[test]
    fn test_cancellation_handle_is_observed_by_context() {
        let ctx = InvocationContext::new(Principal::new("svc", PrincipalKind::Service));
        let handle = ctx.cancellation_handle();
        assert!(!ctx.is_cancelled());
        handle.cancel();
        assert!(ctx.is_cancelled());
        assert!(handle.is_cancelled());
    }
}
