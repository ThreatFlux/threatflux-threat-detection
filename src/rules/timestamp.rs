//! UTC timestamps with the existing rule timestamp wire format.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::str::FromStr;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::parsing::Parsed;
use time::{Date, Duration, Time, UtcDateTime, UtcOffset};

const LEGACY_YEARS: std::ops::RangeInclusive<i32> = -262_143..=262_142;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
const DATE: &[BorrowedFormatItem<'_>] = format_description!("[year range:extended]-[month]-[day]");
const TIME: &[BorrowedFormatItem<'_>] = format_description!(
    version = 2,
    "[hour]:[minute]:[second][optional [.[subsecond]]]"
);
const OFFSET: &[BorrowedFormatItem<'_>] = format_description!(
    version = 2,
    "[offset_hour sign:mandatory][optional [:]][offset_minute]"
);

/// UTC rule-update timestamp with nanosecond precision.
///
/// Serialized timestamps are UTC strings ending in `Z`. Parsing also accepts
/// numeric offsets, which are normalized to UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleTimestamp {
    seconds: i64,
    // A legacy leap second sorts after ordinary fractions of its nominal second.
    nanoseconds: u32,
}

impl RuleTimestamp {
    /// Read the current UTC time.
    pub fn now() -> Self {
        Self::from_utc(UtcDateTime::now())
    }

    /// Return the fractional nanoseconds within the displayed second.
    pub const fn subsec_nanosecond(self) -> u32 {
        self.nanoseconds % NANOS_PER_SECOND
    }

    fn from_utc(value: UtcDateTime) -> Self {
        Self {
            seconds: value.unix_timestamp(),
            nanoseconds: value.nanosecond(),
        }
    }

    pub(super) fn whole_hours_since(self, earlier: Self) -> Option<u64> {
        if self < earlier {
            return None;
        }

        // If the start is in a leap second, counting that second cancels the
        // extra billion in its stored fraction once we reach the next second.
        let seconds = self.seconds - earlier.seconds;
        let borrow = seconds > 0 && self.subsec_nanosecond() < earlier.subsec_nanosecond();
        let seconds = seconds - i64::from(borrow);
        Some(seconds.unsigned_abs() / 3600)
    }
}

/// A timestamp string is malformed or outside the supported range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid UTC or offset timestamp")]
pub struct ParseRuleTimestampError;

impl FromStr for RuleTimestamp {
    type Err = ParseRuleTimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (date, rest) = value
            .trim_start()
            .split_once(['T', 't', ' '])
            .ok_or(ParseRuleTimestampError)?;
        let date = Date::parse(date, DATE).map_err(|_| ParseRuleTimestampError)?;
        if !LEGACY_YEARS.contains(&date.year()) {
            return Err(ParseRuleTimestampError);
        }
        let mut parsed_time = Parsed::new();
        let offset = parsed_time
            .parse_items(rest.trim_start().as_bytes(), TIME)
            .map_err(|_| ParseRuleTimestampError)?;
        let offset = std::str::from_utf8(offset)
            .map_err(|_| ParseRuleTimestampError)?
            .trim_start();
        let offset = if offset.eq_ignore_ascii_case("z") || offset.eq_ignore_ascii_case("utc") {
            UtcOffset::UTC
        } else {
            UtcOffset::parse(offset, OFFSET).map_err(|_| ParseRuleTimestampError)?
        };

        if offset.whole_seconds().unsigned_abs() >= 86_400 {
            return Err(ParseRuleTimestampError);
        }

        let leap_second = parsed_time.second() == Some(60);
        if leap_second {
            parsed_time.set_second(59).ok_or(ParseRuleTimestampError)?;
        }
        let time = Time::try_from(parsed_time).map_err(|_| ParseRuleTimestampError)?;
        let utc = UtcDateTime::new(date, time)
            .checked_sub(Duration::seconds(i64::from(offset.whole_seconds())))
            .ok_or(ParseRuleTimestampError)?;
        if !LEGACY_YEARS.contains(&utc.year()) {
            return Err(ParseRuleTimestampError);
        }
        let mut timestamp = Self::from_utc(utc);
        if leap_second {
            timestamp.nanoseconds += NANOS_PER_SECOND;
        }
        Ok(timestamp)
    }
}

impl fmt::Display for RuleTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let utc = UtcDateTime::from_unix_timestamp(self.seconds).map_err(|_| fmt::Error)?;
        let (year, month, day) = utc.to_calendar_date();
        if (0..=9999).contains(&year) {
            write!(formatter, "{year:04}")?;
        } else {
            write!(formatter, "{year:+05}")?;
        }
        let (hour, minute, second) = utc.as_hms();
        let second = second + u8::from(self.nanoseconds >= NANOS_PER_SECOND);
        write!(
            formatter,
            "-{:02}-{day:02}T{hour:02}:{minute:02}:{second:02}",
            u8::from(month)
        )?;

        let fractional = self.subsec_nanosecond();
        if fractional != 0 {
            if fractional.is_multiple_of(1_000_000) {
                write!(formatter, ".{:03}", fractional / 1_000_000)?;
            } else if fractional.is_multiple_of(1_000) {
                write!(formatter, ".{:06}", fractional / 1_000)?;
            } else {
                write!(formatter, ".{fractional:09}")?;
            }
        }
        formatter.write_str("Z")
    }
}

impl Serialize for RuleTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RuleTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RuleTimestampVisitor;

        impl de::Visitor<'_> for RuleTimestampVisitor {
            type Value = RuleTimestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a timestamp string with a UTC or numeric offset")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<RuleTimestamp, E> {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(RuleTimestampVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_instants_including_leap_seconds() {
        let ordered = [
            "-262143-01-01T00:00:00Z",
            "-0001-12-31T23:59:59Z",
            "0000-01-01T00:00:00Z",
            "1969-12-31T23:59:59.999999999Z",
            "1970-01-01T00:00:00Z",
            "2016-12-31T23:59:59.999999999Z",
            "2016-12-31T23:59:60Z",
            "2016-12-31T23:59:60.999999999Z",
            "2017-01-01T00:00:00Z",
            "+10000-01-01T00:00:00Z",
            "+262142-12-31T23:59:59.999999999Z",
        ]
        .map(|value| {
            let timestamp = value.parse::<RuleTimestamp>().unwrap();
            assert_eq!(timestamp.to_string(), value);
            timestamp
        });
        assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn normalizes_offsets_and_validates_input() {
        for (input, utc) in [
            ("2017-01-01T00:29:60.120+00:30", "2016-12-31T23:59:60.120Z"),
            ("2026-01-01T23:45:05-0030", "2026-01-02T00:15:05Z"),
            ("+262142-12-31T22:59:59-01:00", "+262142-12-31T23:59:59Z"),
            ("-262143-01-01T01:00:00+01:00", "-262143-01-01T00:00:00Z"),
        ] {
            assert_eq!(input.parse::<RuleTimestamp>().unwrap().to_string(), utc);
        }
        for input in [
            "2026-01-02T03:04:05",
            "2026-02-29T03:04:05Z",
            "2026-01-02T24:00:00Z",
            "2026-01-02T03:60:05Z",
            "2026-01-02T03:04:61Z",
            "2026-01-02T03:04:05.Z",
            "2026-01-02T03:04:05+24:00",
            "2026-01-02T03:04:05-00:60",
            "2026-01-02T03:04:05Zjunk",
            "10000-01-01T00:00:00Z",
            "-262144-12-31T23:59:59Z",
            "+262143-01-01T00:00:00Z",
            "-262143-01-01T00:00:00+00:01",
            "+262142-12-31T23:59:59-00:01",
        ] {
            assert!(input.parse::<RuleTimestamp>().is_err(), "{input}");
        }
    }

    #[test]
    fn counts_only_complete_elapsed_hours() {
        let end: RuleTimestamp = "2017-01-01T01:00:00Z".parse().unwrap();
        for (input, hours) in [
            ("2016-12-31T23:59:60.999999999Z", Some(1)),
            ("2017-01-01T00:00:00Z", Some(1)),
            ("2017-01-01T00:00:00.000000001Z", Some(0)),
            ("2017-01-01T01:00:00.000000001Z", None),
        ] {
            assert_eq!(end.whole_hours_since(input.parse().unwrap()), hours);
        }
    }

    #[cfg(feature = "serde-support")]
    #[test]
    fn preserves_legacy_json() {
        for (input, utc, nanos) in [
            ("-262143-01-01T00:00:00Z", "-262143-01-01T00:00:00Z", 0),
            (
                "+262142-12-31T23:59:60.999999999Z",
                "+262142-12-31T23:59:60.999999999Z",
                999_999_999,
            ),
            (
                "2026-01-02T03:04:05.120Z",
                "2026-01-02T03:04:05.120Z",
                120_000_000,
            ),
            (
                "2026-01-02T03:04:05.123456Z",
                "2026-01-02T03:04:05.123456Z",
                123_456_000,
            ),
            (
                "2017-01-01T00:29:60.120001001+00:30",
                "2016-12-31T23:59:60.120001001Z",
                120_001_001,
            ),
        ] {
            let json = serde_json::json!(input);
            let timestamp: RuleTimestamp = serde_json::from_value(json).unwrap();
            assert_eq!(timestamp.subsec_nanosecond(), nanos);
            assert_eq!(
                serde_json::to_value(timestamp).unwrap(),
                serde_json::json!(utc)
            );
        }
        assert!(serde_json::from_str::<RuleTimestamp>("0").is_err());
    }
}
