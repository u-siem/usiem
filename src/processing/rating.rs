//! Shared rating scales: [`Severity`] (how bad) and [`Confidence`] (how
//! sure).
//!
//! These are the one vocabulary for ratings across the crate: a
//! [`crate::processing::signal::Signal`], an
//! [`crate::processing::incident::Incident`] and the enrichment value types
//! ([`crate::processing::enrichment::ThreatInfo`],
//! [`crate::processing::enrichment::AssetInfo`],
//! [`crate::processing::enrichment::UserProfile`]) all use them, so a
//! threat-intel hit becomes a `Signal` without converting scales.
//!
//! [`Criticality`] and [`RiskLevel`] are aliases of [`Severity`] with their
//! own documented meaning; being the same type, they compare with each
//! other directly (e.g. "a high-severity threat against a critical asset").
//!
//! # Example
//!
//! ```
//! use usiem::processing::rating::{Confidence, Severity};
//!
//! // A feed scoring 1-10 maps onto the four levels.
//! assert_eq!(Severity::from_score(8), Severity::High);
//! assert_eq!("critical".parse::<Severity>(), Ok(Severity::Critical));
//! assert!(Severity::High > Severity::Medium);
//!
//! let confidence = Confidence::new(150); // clamped
//! assert_eq!(confidence.as_percent(), 100);
//! assert_eq!(confidence.to_string(), "100%");
//! ```

use std::fmt;
use std::str::FromStr;

/// How bad something is (or would be, if true), ordered from least to most
/// severe.
///
/// Sources that score on a numeric 1-10 scale convert with
/// [`Severity::from_score`]; [`Severity::score`] goes the other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Severity {
    /// Informational or merely suspicious (scores 1-3).
    #[default]
    Low,
    /// Likely malicious, worth monitoring (scores 4-6).
    Medium,
    /// Confirmed malicious, act now (scores 7-9).
    High,
    /// Active attack, emergency response (score 10).
    Critical,
}

/// Business impact of an asset, on the [`Severity`] scale: `Low` for
/// lab/test devices up to `Critical` for core infrastructure.
pub type Criticality = Severity;

/// Security risk of an account, on the [`Severity`] scale: `Low` for
/// standard users up to `Critical` for privileged accounts with broad access.
pub type RiskLevel = Severity;

impl Severity {
    /// Every level, from least to most severe.
    pub const ALL: [Severity; 4] = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// A lowercase string form, e.g. for use as a field value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Map a 1-10 score: 0-3 is `Low`, 4-6 `Medium`, 7-9 `High`, 10 and
    /// above `Critical`.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=3 => Severity::Low,
            4..=6 => Severity::Medium,
            7..=9 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// A representative 1-10 score for this level (2, 5, 8 or 10), for
    /// systems that want a number. `Severity::from_score(s.score()) == s`.
    pub fn score(&self) -> u8 {
        match self {
            Severity::Low => 2,
            Severity::Medium => 5,
            Severity::High => 8,
            Severity::Critical => 10,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The input to [`Severity`]'s or [`Confidence`]'s `FromStr` wasn't valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatingParseError(pub String);

impl fmt::Display for RatingParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid rating: {:?}", self.0)
    }
}

impl std::error::Error for RatingParseError {}

impl FromStr for Severity {
    type Err = RatingParseError;

    /// Case-insensitive level name (`"low"`, `"High"`, ...).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::ALL
            .into_iter()
            .find(|level| level.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| RatingParseError(s.to_string()))
    }
}

/// How sure the source or detection logic is that something is real —
/// distinct from [`Severity`] (how bad it would be if true). A percentage,
/// clamped to `0..=100`.
///
/// # Example
///
/// ```
/// use usiem::processing::rating::Confidence;
///
/// let confidence = Confidence::new(150); // clamped
/// assert_eq!(confidence.as_percent(), 100);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Confidence(u8);

impl Confidence {
    /// No confidence at all (0%).
    pub const NONE: Confidence = Confidence(0);
    /// Full confidence (100%).
    pub const FULL: Confidence = Confidence(100);

    /// Create a `Confidence` from a percentage, clamped to `0..=100`.
    pub fn new(percent: u8) -> Self {
        Self(percent.min(100))
    }

    /// The confidence as a percentage (`0..=100`).
    pub fn as_percent(&self) -> u8 {
        self.0
    }
}

impl From<Confidence> for u8 {
    fn from(confidence: Confidence) -> Self {
        confidence.0
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

impl FromStr for Confidence {
    type Err = RatingParseError;

    /// A percentage, with or without a trailing `%` (`"85"`, `"85%"`);
    /// values above 100 are clamped.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.trim().trim_end_matches('%').trim_end();
        digits
            .parse::<u32>()
            .map(|n| Confidence::new(n.min(100) as u8))
            .map_err(|_| RatingParseError(s.to_string()))
    }
}

/// `Severity` serializes as its lowercase name, `Confidence` as a bare
/// integer — the same shapes [`crate::processing::signal::Signal`] writes
/// into its event fields.
#[cfg(feature = "serde")]
mod serde_impl {
    use super::{Confidence, Severity};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    impl Serialize for Severity {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(self.as_str())
        }
    }

    impl<'de> Deserialize<'de> for Severity {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
            text.parse().map_err(de::Error::custom)
        }
    }

    impl Serialize for Confidence {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_u8(self.0)
        }
    }

    impl<'de> Deserialize<'de> for Confidence {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            u8::deserialize(deserializer).map(Confidence::new)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_score_boundaries() {
        let cases = [
            (0, Severity::Low),
            (1, Severity::Low),
            (3, Severity::Low),
            (4, Severity::Medium),
            (6, Severity::Medium),
            (7, Severity::High),
            (9, Severity::High),
            (10, Severity::Critical),
            (255, Severity::Critical),
        ];
        for (score, want) in cases {
            assert_eq!(Severity::from_score(score), want, "score {score}");
        }
    }

    #[test]
    fn every_score_lands_in_exactly_one_level() {
        for score in 1u8..=10 {
            let hits = Severity::ALL
                .iter()
                .filter(|&&level| Severity::from_score(score) == level)
                .count();
            assert_eq!(hits, 1, "score {score}");
        }
    }

    #[test]
    fn score_round_trips() {
        for level in Severity::ALL {
            assert_eq!(Severity::from_score(level.score()), level);
        }
    }

    #[test]
    fn severity_text_round_trips() {
        for level in Severity::ALL {
            assert_eq!(level.to_string().parse::<Severity>(), Ok(level));
        }
        assert_eq!(" HIGH ".parse::<Severity>(), Ok(Severity::High));
        assert!("severe".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_orders_and_defaults() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::default(), Severity::Low);
        let criticality: Criticality = Severity::Critical;
        let risk: RiskLevel = Severity::High;
        assert!(criticality > risk);
    }

    #[test]
    fn confidence_clamps_formats_and_parses() {
        assert_eq!(Confidence::new(150), Confidence::FULL);
        assert_eq!(Confidence::default(), Confidence::NONE);
        assert_eq!(u8::from(Confidence::new(85)), 85);
        assert_eq!(Confidence::new(85).to_string(), "85%");
        assert_eq!("85".parse::<Confidence>(), Ok(Confidence::new(85)));
        assert_eq!("85 %".parse::<Confidence>(), Ok(Confidence::new(85)));
        assert_eq!("400".parse::<Confidence>(), Ok(Confidence::FULL));
        assert!("high".parse::<Confidence>().is_err());
        assert!(Confidence::new(90) > Confidence::new(10));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shapes() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"Medium\"").unwrap(),
            Severity::Medium
        );
        assert!(serde_json::from_str::<Severity>("\"nope\"").is_err());
        assert_eq!(serde_json::to_string(&Confidence::new(70)).unwrap(), "70");
        assert_eq!(
            serde_json::from_str::<Confidence>("200").unwrap(),
            Confidence::FULL
        );
    }
}
