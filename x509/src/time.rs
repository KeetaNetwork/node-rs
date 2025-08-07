//! Time representation for X.509 certificates.
//!
//! This module provides types and functions for handling time values
//! in X.509 certificates, including ASN.1 time formats like UtcTime and
//! GeneralizedTime.

use crate::error::CertificateError;
use chrono::{DateTime, Datelike, Utc};
use der::asn1::{GeneralizedTime, UtcTime};

/// ASN.1 Time representation (can be either UtcTime or GeneralizedTime)
#[derive(Debug, Clone, PartialEq, Eq, der::Choice)]
pub enum Time {
	UtcTime(UtcTime),
	GeneralizedTime(GeneralizedTime),
}

impl From<Time> for DateTime<Utc> {
	fn from(time: Time) -> Self {
		(&time).into()
	}
}

impl From<&Time> for DateTime<Utc> {
	fn from(time: &Time) -> Self {
		match time {
			Time::UtcTime(utc) => DateTime::from(utc.to_system_time()),
			Time::GeneralizedTime(general) => DateTime::from(general.to_system_time()),
		}
	}
}

impl TryFrom<DateTime<Utc>> for Time {
	type Error = CertificateError;

	fn try_from(datetime: DateTime<Utc>) -> Result<Self, Self::Error> {
		// Per RFC 5280 Section 4.1.2.5:
		// - UTCTime: Represents years 1950-2049 (YY >= 50 -> 19YY, YY < 50 -> 20YY)
		// - GeneralizedTime: Used for dates outside the UTCTime range (before 1950 or 2050+)
		// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1>
		if datetime.year() >= 1950 && datetime.year() < 2050 {
			// Use UtcTime for dates from 1950 to 2049 (inclusive)
			// We need to convert via SystemTime since the der crate requires it
			let system_time: std::time::SystemTime = datetime.into();
			Ok(Time::UtcTime(UtcTime::from_system_time(system_time)?))
		} else {
			// Use GeneralizedTime for dates before 1950 or 2050 and after
			let system_time: std::time::SystemTime = datetime.into();
			Ok(Time::GeneralizedTime(GeneralizedTime::from_system_time(system_time)?))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use chrono::TimeZone;

	#[test]
	fn test_time_from_datetime_utc_range() {
		let datetime_1980 = Utc.with_ymd_and_hms(1980, 1, 1, 0, 0, 0).unwrap();
		let time_1980 = Time::try_from(datetime_1980).unwrap();
		assert!(matches!(time_1980, Time::UtcTime(_)));

		let datetime_2000 = Utc
			.with_ymd_and_hms(2000, 6, 15, 12, 30, 45)
			.unwrap();
		let time_2000 = Time::try_from(datetime_2000).unwrap();
		assert!(matches!(time_2000, Time::UtcTime(_)));

		let datetime_2049 = Utc
			.with_ymd_and_hms(2049, 12, 31, 23, 59, 59)
			.unwrap();
		let time_2049 = Time::try_from(datetime_2049).unwrap();
		assert!(matches!(time_2049, Time::UtcTime(_)));
	}

	#[test]
	fn test_time_from_datetime_generalized_range() {
		let datetime_2050 = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap();
		let time_2050 = Time::try_from(datetime_2050).unwrap();
		assert!(matches!(time_2050, Time::GeneralizedTime(_)));

		let datetime_2100 = Utc
			.with_ymd_and_hms(2100, 7, 4, 16, 20, 30)
			.unwrap();
		let time_2100 = Time::try_from(datetime_2100).unwrap();
		assert!(matches!(time_2100, Time::GeneralizedTime(_)));
	}

	#[test]
	fn test_datetime_from_time_conversion() {
		let original_datetime = Utc
			.with_ymd_and_hms(2023, 8, 15, 14, 30, 0)
			.unwrap();
		let time = Time::try_from(original_datetime).unwrap();

		let converted_datetime: DateTime<Utc> = time.into();
		assert!((converted_datetime.timestamp() - original_datetime.timestamp()).abs() <= 1);
	}

	#[test]
	fn test_datetime_from_time_reference_conversion() {
		let original_datetime = Utc
			.with_ymd_and_hms(1995, 3, 20, 9, 15, 30)
			.unwrap();
		let time = Time::try_from(original_datetime).unwrap();

		let converted_datetime: DateTime<Utc> = (&time).into();
		assert!((converted_datetime.timestamp() - original_datetime.timestamp()).abs() <= 1);
	}

	#[test]
	fn test_time_clone_and_partial_eq() {
		let datetime = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
		let time1 = Time::try_from(datetime).unwrap();
		let time2 = time1.clone();
		assert_eq!(time1, time2);

		let different_datetime = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
		let time3 = Time::try_from(different_datetime).unwrap();
		assert_ne!(time1, time3);
	}

	#[test]
	fn test_time_debug() {
		let datetime = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
		let time = Time::try_from(datetime).unwrap();

		let debug_str = format!("{time:?}");
		assert!(debug_str.contains("UtcTime"));
	}

	#[test]
	fn test_rfc5280_boundary_conditions() {
		// Test the exact RFC 5280 boundary conditions
		// Use dates after 1970 to avoid SystemTime conversion issues
		// Year 1980 should use UtcTime (within 1950-2049 range)
		let year_1980 = Utc.with_ymd_and_hms(1980, 1, 1, 0, 0, 0).unwrap();
		let time_1980 = Time::try_from(year_1980).unwrap();
		assert!(matches!(time_1980, Time::UtcTime(_)));

		// Year 2049 should use UtcTime
		let year_2049 = Utc
			.with_ymd_and_hms(2049, 12, 31, 23, 59, 59)
			.unwrap();
		let time_2049 = Time::try_from(year_2049).unwrap();
		assert!(matches!(time_2049, Time::UtcTime(_)));

		// Year 2050 should use GeneralizedTime
		let year_2050 = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap();
		let time_2050 = Time::try_from(year_2050).unwrap();
		assert!(matches!(time_2050, Time::GeneralizedTime(_)));
	}
}
