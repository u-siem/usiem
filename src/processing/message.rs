//! [`LocalizedMessage`]: a language-independent message — a stable
//! template id, the rendered text in whatever locale it was rendered in,
//! and the template's own substitution parameters — used identically by
//! [`crate::processing::signal::Signal`] and
//! [`crate::processing::action::ActionOutcome`]. Not signal-specific, hence
//! its own module rather than living in `signal.rs`.
//!
//! Rendering (a message catalog, placeholder substitution, locale
//! fallback) is the application's: this crate only carries the result.

use crate::event::field::{FieldValue, Text};
use std::collections::HashMap;

/// A language-independent message: a stable template id, the rendered text
/// in whatever locale it happens to be rendered in right now, and the
/// template's own substitution parameters — so a consumer with its own
/// message catalog can re-render the same message in a different locale
/// later, without re-running detection logic.
///
/// `params` is scoped narrowly to template substitution. It's independent of
/// [`crate::processing::signal::Signal::context`], which may carry
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localized_message_with_param() {
        let message = LocalizedMessage::new(
            "auth.brute_force_threshold",
            "en-US",
            "3 failed logins for alice within 60s",
        )
        .with_param("count", 3);
        assert_eq!(message.params.get("count"), Some(&FieldValue::uint(3)));
        assert!(matches!(message.to_field_value(), FieldValue::Object(_)));
    }
}
