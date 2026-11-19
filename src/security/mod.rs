//! Authorization primitives: who is allowed to do what.
//!
//! This module is **authorization only** — deciding whether an already-
//! identified [`Principal`] may exercise a given [`Permission`]. It has
//! nothing to say about *authentication* (proving who the caller actually
//! is: validating an OAuth token, an API key, a session cookie, mTLS, ...).
//! That stays firmly the consuming application's job, or a satellite
//! crate's — this module never sees a credential, a token, or a network
//! request. An application (or an MCP transport crate) authenticates a
//! caller however it likes and then constructs a [`Principal`] to hand to
//! the rest of this crate through
//! [`crate::processing::context::InvocationContext`].
//!
//! # Why this is in core, unlike inputs and outputs
//!
//! Authorization here isn't an external system this crate would otherwise
//! avoid depending on (the way a firewall API or a Kafka broker is) — it's
//! policy over the framework's *own* surface: which of the actions in
//! [`crate::processing::action::ActionRegistry`] a given caller may even see
//! or fire. Enforcing that centrally, in [`crate::processing::action::ActionRegistry::list_for`]/
//! [`crate::processing::action::ActionRegistry::invoke_as`], is what makes
//! it impossible for a permission check to be silently forgotten at some
//! call site — the same reasoning that put audit-event emission inside
//! `invoke_as` rather than leaving it to each caller.
//!
//! # Design
//!
//! - [`Permission`] is an opaque, dotted/colon-scoped string
//!   (`"action.invoke:block_ip"`, `"dataset.read:threat_intel"`,
//!   `"event.read:tenant/acme"`) — an ecosystem convention, not an enum,
//!   the same way [`crate::processing::action::ActionDescriptor::name`]
//!   capability names are a convention rather than a fixed vocabulary.
//! - [`PermissionPattern`] grants/denies a permission or a `*`-suffixed
//!   prefix of one (`"action.invoke:*"`, `"*"`).
//! - [`Role`] is a named bundle of grant/deny patterns.
//! - [`Principal`] is a caller: a stable id, a [`PrincipalKind`], the role
//!   names it holds, and (for MSSP deployments) the tenants it may act
//!   within.
//! - [`Authorizer`] is the trait a real policy engine implements —
//!   [`RoleAuthorizer`] is this crate's own bundled, static-RBAC
//!   implementation (a mechanism, not a fixed policy), for applications
//!   that don't need anything fancier (OPA, ABAC, a database-backed policy
//!   store, ...).
//!
//! # Security note
//!
//! An [`Authorizer`] only ever *advises* — nothing in this module can force
//! a caller to consult one. [`crate::processing::action::ActionRegistry::invoke`]
//! (the original, unauthenticated call) still exists and bypasses
//! authorization entirely, for trusted in-process code that has no
//! `Principal` to check. Any surface exposed to a less-trusted caller (an
//! MCP server, a web UI) must use
//! [`crate::processing::action::ActionRegistry::list_for`]/
//! [`crate::processing::action::ActionRegistry::invoke_as`] instead of
//! `list`/`invoke` — this crate cannot make that choice for the
//! application.

use crate::event::field::Text;
use crate::processing::message::LocalizedMessage;
use std::collections::HashMap;

/// An opaque, ecosystem-defined permission string, e.g.
/// `"action.invoke:block_ip"`, `"dataset.read:threat_intel"`,
/// `"component.admin:sink/*"`. This crate does not define a fixed
/// vocabulary — see the module docs.
pub type Permission = Text;

/// A grant or deny pattern held by a [`Role`]. Matches a [`Permission`]
/// exactly, or as a `*`-suffixed prefix (`"action.invoke:*"` matches
/// `"action.invoke:block_ip"`; a bare `"*"` matches everything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionPattern(Text);

impl PermissionPattern {
    pub fn new(pattern: impl Into<Text>) -> Self {
        Self(pattern.into())
    }

    /// Whether this pattern matches `permission`.
    pub fn matches(&self, permission: &str) -> bool {
        let pattern: &str = self.0.as_str();
        match pattern.strip_suffix('*') {
            Some(prefix) => permission.starts_with(prefix),
            None => pattern == permission,
        }
    }
}

impl<S: Into<Text>> From<S> for PermissionPattern {
    fn from(value: S) -> Self {
        Self::new(value)
    }
}

/// A named bundle of grant/deny patterns. Denies always take precedence
/// over grants within the same role — see [`RoleAuthorizer::authorize`].
#[derive(Debug, Clone)]
pub struct Role {
    pub name: Text,
    pub description: Text,
    pub grants: Vec<PermissionPattern>,
    pub denies: Vec<PermissionPattern>,
}

impl Role {
    pub fn new(name: impl Into<Text>, description: impl Into<Text>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            grants: Vec::new(),
            denies: Vec::new(),
        }
    }

    /// Add a grant pattern; chainable.
    pub fn grant(mut self, pattern: impl Into<PermissionPattern>) -> Self {
        self.grants.push(pattern.into());
        self
    }

    /// Add a deny pattern; chainable.
    pub fn deny(mut self, pattern: impl Into<PermissionPattern>) -> Self {
        self.denies.push(pattern.into());
        self
    }
}

/// What kind of caller a [`Principal`] represents. Distinguishing `Agent`
/// from `User`/`Service` lets a policy (e.g. [`RoleAuthorizer`]'s default)
/// treat an AI/MCP-driven caller more cautiously than a human analyst or a
/// trusted backend service, without needing a separate permission
/// vocabulary for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Service,
    Agent,
}

/// An identified caller. This crate never constructs one from a credential
/// — the application (or an MCP transport crate) authenticates the caller
/// however it likes, then builds a `Principal` to describe the result.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: Text,
    pub kind: PrincipalKind,
    pub roles: Vec<Text>,
    /// Tenants (MSSP customers) this principal may act within. Empty means
    /// "not tenant-scoped" — an application decides what that implies.
    pub tenants: Vec<Text>,
}

impl Principal {
    pub fn new(id: impl Into<Text>, kind: PrincipalKind) -> Self {
        Self {
            id: id.into(),
            kind,
            roles: Vec::new(),
            tenants: Vec::new(),
        }
    }

    /// A [`PrincipalKind::User`] principal with the given roles; convenience
    /// for tests and small examples.
    pub fn user(id: impl Into<Text>, roles: impl IntoIterator<Item = impl Into<Text>>) -> Self {
        let mut principal = Self::new(id, PrincipalKind::User);
        principal.roles = roles.into_iter().map(Into::into).collect();
        principal
    }

    /// A [`PrincipalKind::Agent`] principal with the given roles —
    /// convenience for an MCP/AI-driven caller.
    pub fn agent(id: impl Into<Text>, roles: impl IntoIterator<Item = impl Into<Text>>) -> Self {
        let mut principal = Self::new(id, PrincipalKind::Agent);
        principal.roles = roles.into_iter().map(Into::into).collect();
        principal
    }

    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<Text>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_tenants(mut self, tenants: impl IntoIterator<Item = impl Into<Text>>) -> Self {
        self.tenants = tenants.into_iter().map(Into::into).collect();
        self
    }
}

/// One authorization check's outcome.
#[derive(Debug, Clone)]
pub enum Decision {
    /// The principal may proceed.
    Allow,
    /// The principal may not proceed; carries a human-readable reason.
    Deny(LocalizedMessage),
    /// The principal has the underlying grant, but the capability is
    /// high-impact enough (see [`AuthzRequest::destructive`]) that a human
    /// must confirm before it actually runs. How "confirm" is presented is
    /// entirely up to the caller — e.g. an MCP transport surfacing this as
    /// an elicitation.
    RequireApproval(LocalizedMessage),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// What is being authorized. Deliberately generic, not action-specific —
/// [`crate::processing::action::ActionRegistry`] is one caller of
/// [`Authorizer::authorize`], but a search/read surface or a future
/// dataset-access check can build one too.
#[derive(Debug, Clone)]
pub struct AuthzRequest<'a> {
    pub permission: &'a str,
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
}

/// The trait a real policy engine implements. This crate ships
/// [`RoleAuthorizer`] as a bundled, policy-free-by-default mechanism;
/// nothing stops an application from wiring in OPA, an ABAC engine, or a
/// database-backed policy store behind the same trait.
pub trait Authorizer: Send + Sync {
    fn authorize(
        &self,
        ctx: &crate::processing::context::InvocationContext,
        request: &AuthzRequest,
    ) -> Decision;
}

/// A trivial [`Authorizer`] that allows everything — useful for tests, for
/// single-tenant deployments with no untrusted callers, and as the
/// implicit behavior of [`crate::processing::action::ActionRegistry::invoke`]
/// (which does not consult an `Authorizer` at all).
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(
        &self,
        _ctx: &crate::processing::context::InvocationContext,
        _request: &AuthzRequest,
    ) -> Decision {
        Decision::Allow
    }
}

/// This crate's bundled static-RBAC [`Authorizer`]: a plain,
/// `Default`-constructible registry of [`Role`]s that application code owns
/// and populates explicitly — no global/singleton policy instance, mirroring
/// [`crate::processing::action::ActionRegistry`]'s own relationship to the
/// actions it holds.
///
/// Resolution order for a given [`AuthzRequest::permission`], across every
/// role the principal holds: any matching `deny` pattern wins outright; a
/// matching `grant` pattern otherwise allows it, unless the request is
/// [`destructive`](AuthzRequest::destructive) and the principal is a
/// [`PrincipalKind::Agent`] — see
/// [`RoleAuthorizer::require_approval_for_agent_destructive`] — in which
/// case it becomes [`Decision::RequireApproval`] instead of an outright
/// allow. No matching grant is a [`Decision::Deny`] (deny-by-default).
pub struct RoleAuthorizer {
    roles: HashMap<Text, Role>,
    require_approval_for_agent_destructive: bool,
}

impl RoleAuthorizer {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            require_approval_for_agent_destructive: true,
        }
    }

    /// Register or replace a role; chainable.
    pub fn with_role(mut self, role: Role) -> Self {
        self.roles.insert(role.name.clone(), role);
        self
    }

    /// Toggle whether a destructive capability, otherwise allowed, requires
    /// human approval when the caller is a [`PrincipalKind::Agent`].
    /// Defaults to `true` — the cautious posture for an AI-driven caller.
    pub fn require_approval_for_agent_destructive(mut self, value: bool) -> Self {
        self.require_approval_for_agent_destructive = value;
        self
    }

    /// Seeded with a small set of illustrative starter roles
    /// (`viewer`, `analyst`, `responder`, `admin`, `agent_readonly`) — a
    /// convenience for getting started and for examples/tests, not a fixed
    /// vocabulary this crate expects real deployments to keep. Nothing else
    /// in this crate depends on these names existing.
    pub fn with_default_roles(self) -> Self {
        self.with_role(
            Role::new(
                "viewer",
                "Read-only visibility into SIEM data and capabilities",
            )
            .grant("action.list:*")
            .grant("*:read_only"),
        )
        .with_role(
            Role::new(
                "analyst",
                "Investigates and searches, cannot fire response actions",
            )
            .grant("action.list:*")
            .grant("*:read_only")
            .grant("dataset.read:*"),
        )
        .with_role(
            Role::new("responder", "May fire response/SOAR actions")
                .grant("action.list:*")
                .grant("*:read_only")
                .grant("action.invoke:*"),
        )
        .with_role(
            Role::new(
                "admin",
                "Unrestricted — configuration, response, and read access",
            )
            .grant("*"),
        )
        .with_role(
            Role::new(
                "agent_readonly",
                "An AI/MCP caller restricted to read-only capabilities",
            )
            .grant("action.list:*")
            .grant("*:read_only"),
        )
    }

    fn resolve<'a>(&'a self, principal: &'a Principal) -> impl Iterator<Item = &'a Role> {
        principal
            .roles
            .iter()
            .filter_map(|name| self.roles.get(name.as_str()))
    }
}

impl Default for RoleAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Authorizer for RoleAuthorizer {
    fn authorize(
        &self,
        ctx: &crate::processing::context::InvocationContext,
        request: &AuthzRequest,
    ) -> Decision {
        let roles: Vec<&Role> = self.resolve(&ctx.principal).collect();

        // A read_only request also satisfies any pattern scoped to
        // "*:read_only" — a convenience so a role doesn't have to enumerate
        // every read-only permission by name. This is purely additive to
        // matching `request.permission` directly.
        let read_only_alias = "*:read_only";

        let denied = roles.iter().any(|role| {
            role.denies
                .iter()
                .any(|pattern| pattern.matches(request.permission))
        });
        if denied {
            return Decision::Deny(LocalizedMessage::new(
                "authz.denied",
                "en-US",
                format!("permission '{}' explicitly denied", request.permission),
            ));
        }

        let granted = roles.iter().any(|role| {
            role.grants.iter().any(|pattern| {
                pattern.matches(request.permission)
                    || (request.read_only && pattern.matches(read_only_alias))
            })
        });

        if !granted {
            return Decision::Deny(LocalizedMessage::new(
                "authz.no_grant",
                "en-US",
                format!(
                    "no role held by '{}' grants '{}'",
                    ctx.principal.id, request.permission
                ),
            ));
        }

        if request.destructive
            && self.require_approval_for_agent_destructive
            && ctx.principal.kind == PrincipalKind::Agent
        {
            return Decision::RequireApproval(LocalizedMessage::new(
                "authz.approval_required",
                "en-US",
                format!(
                    "'{}' is destructive and '{}' is an agent principal — human approval required",
                    request.permission, ctx.principal.id
                ),
            ));
        }

        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processing::context::InvocationContext;

    fn ctx_for(principal: Principal) -> InvocationContext {
        InvocationContext::new(principal)
    }

    #[test]
    fn test_permission_pattern_exact_and_wildcard() {
        assert!(PermissionPattern::new("action.invoke:block_ip").matches("action.invoke:block_ip"));
        assert!(
            !PermissionPattern::new("action.invoke:block_ip").matches("action.invoke:isolate_host")
        );
        assert!(PermissionPattern::new("action.invoke:*").matches("action.invoke:block_ip"));
        assert!(PermissionPattern::new("*").matches("anything.at.all"));
    }

    #[test]
    fn test_deny_by_default_with_no_roles() {
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = ctx_for(Principal::user("nobody", Vec::<&str>::new()));
        let decision = authz.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:block_ip",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_viewer_cannot_invoke_destructive_action() {
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = ctx_for(Principal::user("alice", ["viewer"]));
        let decision = authz.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:block_ip",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_responder_can_invoke_destructive_action() {
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = ctx_for(Principal::user("bob", ["responder"]));
        let decision = authz.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:block_ip",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn test_agent_needs_approval_for_destructive_even_with_grant() {
        let authz = RoleAuthorizer::new().with_default_roles();
        let ctx = ctx_for(Principal::agent("copilot", ["responder"]));
        let decision = authz.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:block_ip",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(matches!(decision, Decision::RequireApproval(_)));
    }

    #[test]
    fn test_deny_overrides_grant() {
        let authz = RoleAuthorizer::new().with_role(
            Role::new("scoped_responder", "responder minus block_ip")
                .grant("action.invoke:*")
                .deny("action.invoke:block_ip"),
        );
        let ctx = ctx_for(Principal::user("carol", ["scoped_responder"]));
        let decision = authz.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:block_ip",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(matches!(decision, Decision::Deny(_)));

        let other = authz.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:isolate_host",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(other.is_allow());
    }

    #[test]
    fn test_allow_all_always_allows() {
        let ctx = ctx_for(Principal::user("anyone", Vec::<&str>::new()));
        let decision = AllowAll.authorize(
            &ctx,
            &AuthzRequest {
                permission: "action.invoke:anything",
                read_only: false,
                destructive: true,
                idempotent: false,
            },
        );
        assert!(decision.is_allow());
    }
}
