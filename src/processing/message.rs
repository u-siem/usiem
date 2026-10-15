//! [`LocalizedMessage`]: a language-independent message — a stable
//! template id, the rendered text in whatever locale it was rendered in,
//! and the template's own substitution parameters — used identically by
//! [`crate::processing::signal::Signal`],
//! [`crate::processing::incident::Incident`], and
//! [`crate::processing::action::ActionOutcome`]. Not signal-specific, hence
//! its own module rather than living in `signal.rs`.
//!
//! Also provides [`Template`]/[`TemplateRegistry`]: a small, centralized
//! message-catalog and `{key}`-placeholder renderer that produces a
//! `LocalizedMessage` from a `template_id` instead of every call site
//! hand-writing already-rendered `text` inline (as
//! [`LocalizedMessage::new`] still allows, for tests or one-off messages
//! with no catalog entry).
//!
//! # Why this ships a real implementation, unlike `Sink`/`Action`
//!
//! Every other extension point in `processing` (`Sink`, `Action`,
//! `GeoIpDataset`/`ThreatIntelDataset`) is a contract only, because it
//! wraps an external system this crate has no business depending on
//! (Kafka, a firewall API, a GeoIP database). Template rendering has no
//! such external dependency — it's pure, in-memory string substitution
//! that every consuming application would otherwise reimplement
//! identically. Centralizing it here removes duplicated work without
//! taking on the kind of dependency this crate otherwise avoids.
//!
//! [`TemplateRegistry`] still follows this crate's registry convention
//! exactly (see [`crate::processing::action::ActionRegistry`]'s module
//! docs): a plain, `Default`-constructible, `HashMap`-backed struct that
//! application code owns and populates explicitly — no global/static
//! catalog instance.

use crate::event::field::{FieldValue, Text};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static PLACEHOLDER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([A-Za-z0-9_.]+)\}").expect("invalid placeholder regex"));

/// A language-independent message: a stable template id, the rendered text
/// in whatever locale it happens to be rendered in right now, and the
/// template's own substitution parameters — so a consumer with its own
/// message catalog (or [`TemplateRegistry`], this crate's own minimal one)
/// can re-render the same message in a different locale later, without
/// re-running detection logic. [`LocalizedMessage::new`] remains available
/// for constructing one directly (e.g. in tests, or for a message with no
/// catalog entry at all) — [`TemplateRegistry::render`] is simply the
/// preferred path when a catalog exists.
///
/// `params` is scoped narrowly to template substitution. It's independent of
/// [`crate::processing::signal::Signal::context`]/
/// [`crate::processing::incident::Incident::context`], which may carry
/// supporting evidence that never appears in `text` at all.
#[derive(Debug, Clone)]
pub struct LocalizedMessage {
    /// A stable, application-defined message-catalog key, e.g.
    /// `"auth.brute_force_threshold"`. Language-independent by construction.
    pub template_id: Text,
    /// The language `text` is rendered in right now (e.g. `"en-US"`).
    pub locale: Text,
    /// The rendered message text, in `locale`.
    pub text: String,
    /// The template's substitution values, so `text` can be re-rendered in
    /// another locale from `template_id` + `params` alone.
    pub params: HashMap<String, FieldValue>,
}

impl LocalizedMessage {
    /// Create a message with no substitution parameters.
    pub fn new(
        template_id: impl Into<Text>,
        locale: impl Into<Text>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            template_id: template_id.into(),
            locale: locale.into(),
            text: text.into(),
            params: HashMap::new(),
        }
    }

    /// Attach a template substitution value; chainable.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<FieldValue>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// `FieldValue::Object` form: `{template_id, locale, text, params}`.
    pub(crate) fn to_field_value(&self) -> FieldValue {
        let mut object = HashMap::new();
        object.insert(
            Text::from("template_id"),
            FieldValue::Str(self.template_id.clone()),
        );
        object.insert(Text::from("locale"), FieldValue::Str(self.locale.clone()));
        object.insert(Text::from("text"), FieldValue::string(self.text.clone()));
        object.insert(
            Text::from("params"),
            FieldValue::Object(
                self.params
                    .iter()
                    .map(|(k, v)| (Text::from(k.clone()), v.clone()))
                    .collect(),
            ),
        );
        FieldValue::Object(object)
    }
}

/// A stable, application-defined message-catalog entry: a `template_id`
/// plus one format string per locale, each containing `{key}`-style
/// placeholders filled from a [`LocalizedMessage::params`] map at render
/// time. See [`TemplateRegistry::render`].
///
/// Placeholder keys may contain letters, digits, `_`, and `.`
/// (`[A-Za-z0-9_.]+`) — there is no escaping for a literal `{`/`}`.
#[derive(Debug, Clone)]
pub struct Template {
    template_id: Text,
    formats: HashMap<Text, String>,
}

impl Template {
    /// Create a template with no locale variants yet.
    pub fn new(template_id: impl Into<Text>) -> Self {
        Self {
            template_id: template_id.into(),
            formats: HashMap::new(),
        }
    }

    /// Attach a format string for one locale; chainable. Overwrites any
    /// previous format string for the same locale.
    pub fn with_locale(mut self, locale: impl Into<Text>, format: impl Into<String>) -> Self {
        self.formats.insert(locale.into(), format.into());
        self
    }

    /// This template's stable catalog key.
    pub fn template_id(&self) -> &Text {
        &self.template_id
    }

    /// This template's raw, unrendered format string for `locale`, if one is
    /// registered — e.g. for a caller that wants to inspect which `{key}`
    /// placeholders a template references without actually rendering it
    /// (see [`crate::mcp`]'s use of this for MCP prompt arguments).
    pub fn format(&self, locale: &str) -> Option<&str> {
        self.formats.get(locale).map(String::as_str)
    }

    /// Every locale this template has a format string registered for.
    pub fn locales(&self) -> impl Iterator<Item = &Text> {
        self.formats.keys()
    }
}

/// Errors from [`TemplateRegistry::render`]/[`TemplateRegistry::rerender`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// No [`Template`] is registered under this `template_id`.
    TemplateNotFound(Text),
    /// `template_id` is registered, but has no format string for `locale`.
    /// No automatic fallback locale is used — see the module docs.
    LocaleNotFound { template_id: Text, locale: Text },
    /// The locale's format string references a placeholder key with no
    /// matching entry in the `params` passed to `render`.
    MissingParam {
        template_id: Text,
        locale: Text,
        key: Text,
    },
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::TemplateNotFound(id) => {
                write!(f, "no template registered for template_id {id:?}")
            }
            TemplateError::LocaleNotFound {
                template_id,
                locale,
            } => write!(
                f,
                "template {template_id:?} has no format string for locale {locale:?}"
            ),
            TemplateError::MissingParam {
                template_id,
                locale,
                key,
            } => write!(
                f,
                "template {template_id:?} ({locale:?}) references undefined param {key:?}"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// A named, runtime-discoverable catalog mapping a `template_id` to its
/// registered [`Template`]. See the module docs for why this ships a real
/// implementation (unlike [`crate::processing::sink::Sink`]/
/// [`crate::processing::action::Action`]) while still following this
/// crate's app-owned, non-global registry convention.
///
/// # Example
///
/// ```
/// use usiem::processing::message::{Template, TemplateRegistry};
/// use usiem::event::field::FieldValue;
/// use std::collections::HashMap;
///
/// let mut registry = TemplateRegistry::new();
/// registry.register(
///     Template::new("auth.brute_force_threshold")
///         .with_locale("en-US", "{count} failed logins for {user} within 60s"),
/// );
///
/// let mut params = HashMap::new();
/// params.insert("count".to_string(), FieldValue::uint(3));
/// params.insert("user".to_string(), FieldValue::str("alice"));
///
/// let message = registry
///     .render("auth.brute_force_threshold", "en-US", params)
///     .unwrap();
///
/// assert_eq!(message.text, "3 failed logins for alice within 60s");
/// ```
#[derive(Default)]
pub struct TemplateRegistry {
    templates: HashMap<Text, Template>,
}

impl TemplateRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    /// Register a template, replacing any previous registration under the
    /// same `template_id` — unlike
    /// [`crate::processing::action::ActionRegistry::register`], a
    /// `template_id` names exactly one catalog entry, not many providers.
    pub fn register(&mut self, template: Template) {
        self.templates
            .insert(template.template_id.clone(), template);
    }

    /// Look up a registered template by id, e.g. for introspection.
    pub fn get(&self, template_id: &str) -> Option<&Template> {
        self.templates.get(template_id)
    }

    /// Every registered `template_id`.
    pub fn list(&self) -> Vec<&Text> {
        self.templates.keys().collect()
    }

    /// Render `template_id` in `locale` by substituting `{key}` placeholders
    /// in the registered format string from `params`. `params` is moved
    /// into the returned [`LocalizedMessage::params`] rather than cloned.
    ///
    /// No locale fallback: an unregistered `(template_id, locale)` pair is
    /// always [`TemplateError::LocaleNotFound`], never silently rendered in
    /// a different locale — see the module docs.
    pub fn render(
        &self,
        template_id: &str,
        locale: &str,
        params: HashMap<String, FieldValue>,
    ) -> Result<LocalizedMessage, TemplateError> {
        let template = self
            .templates
            .get(template_id)
            .ok_or_else(|| TemplateError::TemplateNotFound(Text::from(template_id)))?;
        let format = template
            .formats
            .get(locale)
            .ok_or_else(|| TemplateError::LocaleNotFound {
                template_id: Text::from(template_id),
                locale: Text::from(locale),
            })?;
        let text = substitute(format, &params, template_id, locale)?;
        Ok(LocalizedMessage {
            template_id: Text::from(template_id),
            locale: Text::from(locale),
            text,
            params,
        })
    }

    /// Re-render an existing [`LocalizedMessage`] in a different `locale`,
    /// reusing its `template_id` and `params` — the concrete "re-render the
    /// same message in a different locale later, without re-running
    /// detection logic" use case described in [`LocalizedMessage`]'s own
    /// docs. A `Signal`/`Incident`/`ActionOutcome` already carries a
    /// `message` rendered in whatever locale detection ran in; hand it
    /// straight to the registry to get it back in another locale.
    pub fn rerender(
        &self,
        message: &LocalizedMessage,
        locale: &str,
    ) -> Result<LocalizedMessage, TemplateError> {
        self.render(&message.template_id, locale, message.params.clone())
    }
}

/// Fill `{key}` placeholders in `format` from `params`. `FieldValue::Str`
/// substitutes borrowed (no extra allocation); every other variant uses its
/// existing `Display` impl.
fn substitute(
    format: &str,
    params: &HashMap<String, FieldValue>,
    template_id: &str,
    locale: &str,
) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(format.len());
    let mut last_end = 0;
    for capture in PLACEHOLDER_REGEX.captures_iter(format) {
        let whole = capture.get(0).expect("group 0 always matches");
        let key = capture
            .get(1)
            .expect("placeholder regex always captures group 1")
            .as_str();
        out.push_str(&format[last_end..whole.start()]);
        match params.get(key) {
            Some(FieldValue::Str(s)) => out.push_str(s),
            Some(value) => out.push_str(&value.to_string()),
            None => {
                return Err(TemplateError::MissingParam {
                    template_id: Text::from(template_id),
                    locale: Text::from(locale),
                    key: Text::from(key),
                });
            }
        }
        last_end = whole.end();
    }
    out.push_str(&format[last_end..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> LocalizedMessage {
        LocalizedMessage::new(
            "auth.brute_force_threshold",
            "en-US",
            "3 failed logins for alice within 60s",
        )
        .with_param("count", 3)
    }

    #[test]
    fn test_localized_message_with_param() {
        let message = sample_message();
        assert_eq!(message.params.get("count"), Some(&FieldValue::uint(3)));
    }

    #[test]
    fn test_render_substitutes_str_and_non_str_params() {
        let mut registry = TemplateRegistry::new();
        registry.register(
            Template::new("auth.brute_force_threshold")
                .with_locale("en-US", "{count} failed logins for {user} within 60s"),
        );

        let mut params = HashMap::new();
        params.insert("count".to_string(), FieldValue::uint(3));
        params.insert("user".to_string(), FieldValue::str("alice"));

        let message = registry
            .render("auth.brute_force_threshold", "en-US", params)
            .unwrap();

        assert_eq!(message.text, "3 failed logins for alice within 60s");
        assert_eq!(message.template_id, "auth.brute_force_threshold");
        assert_eq!(message.locale, "en-US");
    }

    #[test]
    fn test_render_missing_param_errors() {
        let mut registry = TemplateRegistry::new();
        registry.register(
            Template::new("auth.brute_force_threshold")
                .with_locale("en-US", "{count} failed logins"),
        );

        let err = registry
            .render("auth.brute_force_threshold", "en-US", HashMap::new())
            .unwrap_err();

        assert_eq!(
            err,
            TemplateError::MissingParam {
                template_id: Text::from("auth.brute_force_threshold"),
                locale: Text::from("en-US"),
                key: Text::from("count"),
            }
        );
    }

    #[test]
    fn test_render_unknown_template_errors() {
        let registry = TemplateRegistry::new();

        let err = registry
            .render("no.such.template", "en-US", HashMap::new())
            .unwrap_err();

        assert_eq!(
            err,
            TemplateError::TemplateNotFound(Text::from("no.such.template"))
        );
    }

    #[test]
    fn test_render_unknown_locale_errors_with_no_fallback() {
        let mut registry = TemplateRegistry::new();
        registry.register(Template::new("auth.brute_force_threshold").with_locale("en-US", "ok"));

        let err = registry
            .render("auth.brute_force_threshold", "es-ES", HashMap::new())
            .unwrap_err();

        assert_eq!(
            err,
            TemplateError::LocaleNotFound {
                template_id: Text::from("auth.brute_force_threshold"),
                locale: Text::from("es-ES"),
            }
        );
    }

    #[test]
    fn test_register_overwrites_existing_template() {
        let mut registry = TemplateRegistry::new();
        registry
            .register(Template::new("auth.brute_force_threshold").with_locale("en-US", "first"));
        registry
            .register(Template::new("auth.brute_force_threshold").with_locale("en-US", "second"));

        assert_eq!(registry.list().len(), 1);
        let message = registry
            .render("auth.brute_force_threshold", "en-US", HashMap::new())
            .unwrap();
        assert_eq!(message.text, "second");
    }

    #[test]
    fn test_rerender_produces_equivalent_message_in_another_locale() {
        let mut registry = TemplateRegistry::new();
        registry.register(
            Template::new("auth.brute_force_threshold")
                .with_locale("en-US", "{count} failed logins")
                .with_locale("es-ES", "{count} inicios de sesion fallidos"),
        );

        let mut params = HashMap::new();
        params.insert("count".to_string(), FieldValue::uint(3));
        let en = registry
            .render("auth.brute_force_threshold", "en-US", params)
            .unwrap();

        let es = registry.rerender(&en, "es-ES").unwrap();

        assert_eq!(es.text, "3 inicios de sesion fallidos");
        assert_eq!(es.template_id, en.template_id);
        assert_eq!(es.params, en.params);
    }

    #[test]
    fn test_rerender_propagates_locale_not_found() {
        let mut registry = TemplateRegistry::new();
        registry.register(Template::new("auth.brute_force_threshold").with_locale("en-US", "ok"));

        let message = registry
            .render("auth.brute_force_threshold", "en-US", HashMap::new())
            .unwrap();

        let err = registry.rerender(&message, "es-ES").unwrap_err();

        assert_eq!(
            err,
            TemplateError::LocaleNotFound {
                template_id: Text::from("auth.brute_force_threshold"),
                locale: Text::from("es-ES"),
            }
        );
    }
}
