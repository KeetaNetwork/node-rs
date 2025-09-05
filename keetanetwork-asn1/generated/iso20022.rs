#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
use rasn::prelude::*;
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct Address {
	#[rasn(identifier = "addressLines")]
	pub address_lines: Option<AddressLines>,
	#[rasn(identifier = "addressType")]
	pub address_type: Option<AddressType>,
	#[rasn(identifier = "buildingNumber")]
	pub building_number: Option<BuildingNumber>,
	pub country: Option<Country>,
	#[rasn(identifier = "countrySubDivision")]
	pub country_sub_division: Option<CountrySubDivision>,
	pub department: Option<Department>,
	#[rasn(identifier = "postalCode")]
	pub postal_code: Option<PostalCode>,
	#[rasn(identifier = "streetName")]
	pub street_name: Option<StreetName>,
	#[rasn(identifier = "subDepartment")]
	pub sub_department: Option<SubDepartment>,
	#[rasn(identifier = "townName")]
	pub town_name: Option<TownName>,
}
impl Address {
	pub fn new(
		address_lines: Option<AddressLines>,
		address_type: Option<AddressType>,
		building_number: Option<BuildingNumber>,
		country: Option<Country>,
		country_sub_division: Option<CountrySubDivision>,
		department: Option<Department>,
		postal_code: Option<PostalCode>,
		street_name: Option<StreetName>,
		sub_department: Option<SubDepartment>,
		town_name: Option<TownName>,
	) -> Self {
		Self {
			address_lines,
			address_type,
			building_number,
			country,
			country_sub_division,
			department,
			postal_code,
			street_name,
			sub_department,
			town_name,
		}
	}
}
#[doc = " Anonymous SEQUENCE OF member "]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate, identifier = "UTF8String")]
pub struct AnonymousAddressLines(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.2.6"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct AddressLines(pub SequenceOf<AnonymousAddressLines>);
#[doc = "1.3.6.1.4.1.62675.1.7.1"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum AddressType {
	#[rasn(tag(context, 0))]
	code(Utf8String),
	#[rasn(tag(context, 1))]
	proprietary(Utf8String),
}
#[doc = "1.3.6.1.4.1.62675.1.0"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct BirthDate(pub GeneralizedTime);
#[doc = "1.3.6.1.4.1.62675.1.2.4"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct BuildingNumber(pub Utf8String);
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct ContactDetails {
	pub department: Option<Department>,
	#[rasn(identifier = "emailAddress")]
	pub email_address: Option<EmailAddress>,
	#[rasn(identifier = "emailPurpose")]
	pub email_purpose: Option<EmailAddressPurpose>,
	#[rasn(identifier = "faxNumber")]
	pub fax_number: Option<PhoneNumber>,
	#[rasn(identifier = "fullName")]
	pub full_name: Option<FullName>,
	#[rasn(identifier = "jobResponsibility")]
	pub job_responsibility: Option<JobResponsibility>,
	#[rasn(identifier = "jobTitle")]
	pub job_title: Option<JobTitle>,
	#[rasn(identifier = "mobileNumber")]
	pub mobile_number: Option<PhoneNumber>,
	#[rasn(identifier = "namePrefix")]
	pub name_prefix: Option<NamePrefixCode>,
	pub other: Option<SequenceOf<OtherContact>>,
	#[rasn(identifier = "phoneNumber")]
	pub phone_number: Option<PhoneNumber>,
	#[rasn(identifier = "preferredMethod")]
	pub preferred_method: Option<PreferredContactMethodCode>,
}
impl ContactDetails {
	pub fn new(
		department: Option<Department>,
		email_address: Option<EmailAddress>,
		email_purpose: Option<EmailAddressPurpose>,
		fax_number: Option<PhoneNumber>,
		full_name: Option<FullName>,
		job_responsibility: Option<JobResponsibility>,
		job_title: Option<JobTitle>,
		mobile_number: Option<PhoneNumber>,
		name_prefix: Option<NamePrefixCode>,
		other: Option<SequenceOf<OtherContact>>,
		phone_number: Option<PhoneNumber>,
		preferred_method: Option<PreferredContactMethodCode>,
	) -> Self {
		Self {
			department,
			email_address,
			email_purpose,
			fax_number,
			full_name,
			job_responsibility,
			job_title,
			mobile_number,
			name_prefix,
			other,
			phone_number,
			preferred_method,
		}
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct Country(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.2.0"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct CountrySubDivision(pub Utf8String);
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct DateAndPlaceOfBirth {
	#[rasn(identifier = "birthDate")]
	pub birth_date: BirthDate,
	#[rasn(identifier = "cityOfBirth")]
	pub city_of_birth: TownName,
	#[rasn(identifier = "countryOfBirth")]
	pub country_of_birth: Country,
	#[rasn(identifier = "provinceOfBirth")]
	pub province_of_birth: Option<CountrySubDivision>,
}
impl DateAndPlaceOfBirth {
	pub fn new(
		birth_date: BirthDate,
		city_of_birth: TownName,
		country_of_birth: Country,
		province_of_birth: Option<CountrySubDivision>,
	) -> Self {
		Self { birth_date, city_of_birth, country_of_birth, province_of_birth }
	}
}
#[doc = "1.3.6.1.4.1.62675.1.2.8"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct Department(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.1"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct EmailAddress(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.2.9"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct EmailAddressPurpose(pub Utf8String);
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum EntityType {
	#[rasn(tag(context, 0))]
	organization(OrganizationIdentification),
	#[rasn(tag(context, 1))]
	person(PersonIdentification),
}
#[doc = "1.3.6.1.4.1.62675.1.3.0"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct FullName(pub Utf8String);
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct GenericOrganizationIdentification {
	pub id: Id,
	pub issuer: Option<Issuer>,
	#[rasn(identifier = "schemeName")]
	pub scheme_name: Option<OrganizationIdentificationSchemeNameChoice>,
}
impl GenericOrganizationIdentification {
	pub fn new(
		id: Id,
		issuer: Option<Issuer>,
		scheme_name: Option<OrganizationIdentificationSchemeNameChoice>,
	) -> Self {
		Self { id, issuer, scheme_name }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct GenericPersonIdentification {
	pub id: Id,
	pub issuer: Option<Issuer>,
	#[rasn(identifier = "schemeName")]
	pub scheme_name: Option<PersonIdentificationSchemeNameChoice>,
}
impl GenericPersonIdentification {
	pub fn new(id: Id, issuer: Option<Issuer>, scheme_name: Option<PersonIdentificationSchemeNameChoice>) -> Self {
		Self { id, issuer, scheme_name }
	}
}
#[doc = "1.3.6.1.4.1.62675.1.6.1"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct Id(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.7"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct Issuer(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.6"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct JobResponsibility(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.4"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct JobTitle(pub Utf8String);
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
#[rasn(enumerated)]
pub enum NamePrefixCode {
	DOCT = 0,
	MIST = 1,
	MISS = 2,
	MIKS = 3,
	MME = 4,
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct OrganizationIdentification {
	pub bic: Option<Utf8String>,
	pub lei: Option<Utf8String>,
	pub other: Option<SequenceOf<GenericOrganizationIdentification>>,
}
impl OrganizationIdentification {
	pub fn new(
		bic: Option<Utf8String>,
		lei: Option<Utf8String>,
		other: Option<SequenceOf<GenericOrganizationIdentification>>,
	) -> Self {
		Self { bic, lei, other }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum OrganizationIdentificationSchemeNameChoice {
	#[rasn(tag(context, 0))]
	code(Utf8String),
	#[rasn(tag(context, 1))]
	proprietary(Utf8String),
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct OtherContact {
	#[rasn(identifier = "channelType")]
	pub channel_type: Utf8String,
	pub id: Option<Id>,
}
impl OtherContact {
	pub fn new(channel_type: Utf8String, id: Option<Id>) -> Self {
		Self { channel_type, id }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(automatic_tags)]
pub struct PersonIdentification {
	#[rasn(identifier = "dateAndPlaceOfBirth")]
	pub date_and_place_of_birth: Option<DateAndPlaceOfBirth>,
	pub other: Option<SequenceOf<GenericPersonIdentification>>,
}
impl PersonIdentification {
	pub fn new(
		date_and_place_of_birth: Option<DateAndPlaceOfBirth>,
		other: Option<SequenceOf<GenericPersonIdentification>>,
	) -> Self {
		Self { date_and_place_of_birth, other }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PersonIdentificationSchemeNameChoice {
	#[rasn(tag(context, 0))]
	code(Utf8String),
	#[rasn(tag(context, 1))]
	proprietary(Utf8String),
}
#[doc = "1.3.6.1.4.1.62675.1.3"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct PhoneNumber(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.2.1"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct PostalCode(pub Utf8String);
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
#[rasn(enumerated)]
pub enum PreferredContactMethodCode {
	LETT = 0,
	MAIL = 1,
	PHON = 2,
	FAXX = 3,
	CELL = 4,
}
#[doc = "1.3.6.1.4.1.62675.1.2.5"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct StreetName(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.2.7"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct SubDepartment(pub Utf8String);
#[doc = "1.3.6.1.4.1.62675.1.2.3"]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct TownName(pub Utf8String);
