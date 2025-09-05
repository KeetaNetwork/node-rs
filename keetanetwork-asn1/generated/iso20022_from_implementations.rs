//! Generated From implementations for wrapper types
//!
//! This module provides convenient From implementations for all wrapper types
//! that delegate to primitive types like Utf8String and GeneralizedTime,
//! making them more ergonomic to use.

use super::iso20022::*;

impl From<String> for BuildingNumber {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for BuildingNumber {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for Country {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for Country {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for CountrySubDivision {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for CountrySubDivision {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for Department {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for Department {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for EmailAddress {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for EmailAddress {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for EmailAddressPurpose {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for EmailAddressPurpose {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for FullName {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for FullName {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for Id {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for Id {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for Issuer {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for Issuer {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for JobResponsibility {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for JobResponsibility {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for JobTitle {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for JobTitle {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for PhoneNumber {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for PhoneNumber {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for PostalCode {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for PostalCode {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for StreetName {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for StreetName {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for SubDepartment {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for SubDepartment {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<String> for TownName {
	fn from(value: String) -> Self {
		Self(value)
	}
}

impl From<&str> for TownName {
	fn from(value: &str) -> Self {
		Self(value.into())
	}
}

impl From<rasn::types::GeneralizedTime> for BirthDate {
	fn from(value: rasn::types::GeneralizedTime) -> Self {
		Self(value)
	}
}

#[cfg(feature = "chrono")]
impl From<std::time::SystemTime> for BirthDate {
	fn from(value: std::time::SystemTime) -> Self {
		Self(chrono::DateTime::<chrono::Utc>::from(value).into())
	}
}

#[cfg(feature = "chrono")]
impl From<chrono::DateTime<chrono::Utc>> for BirthDate {
	fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
		Self(value.into())
	}
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveDate> for BirthDate {
	fn from(value: chrono::NaiveDate) -> Self {
		Self(value.and_hms_opt(0, 0, 0).unwrap().and_utc().fixed_offset())
	}
}

// Default implementations for types with default fields

impl Default for Address {
	fn default() -> Self {
		Self::new(None, None, None, None, None, None, None, None, None, None)
	}
}

impl Default for ContactDetails {
	fn default() -> Self {
		Self::new(None, None, None, None, None, None, None, None, None, None, None, None)
	}
}

impl Default for OrganizationIdentification {
	fn default() -> Self {
		Self::new(None, None, None)
	}
}

impl Default for OtherContact {
	fn default() -> Self {
		Self::new(Default::default(), None)
	}
}

impl Default for PersonIdentification {
	fn default() -> Self {
		Self::new(None, None)
	}
}
