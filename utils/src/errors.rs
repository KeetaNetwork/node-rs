//! Error handling macros for the node-rs project
//!
//! This module contains macros that reduce boilerplate when implementing
//! error conversions and From traits for error enums.

/// Macro to generate From implementations for error enums
///
/// This macro reduces boilerplate when implementing From trait for error types
/// that wrap other error types in enum variants.
///
/// # Example
/// ```rust
/// use utils::impl_source_error_from;
///
/// #[derive(Debug)]
/// enum MyError {
///     IoError { source: std::io::Error },
///     ParseError { source: std::num::ParseIntError },
/// }
///
/// impl_source_error_from!(MyError, {
///     std::io::Error => IoError,
///     std::num::ParseIntError => ParseError,
/// });
/// ```
#[macro_export]
macro_rules! impl_source_error_from {
	($target_error:ty, { $($source_type:ty => $variant:ident),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(source: $source_type) -> Self {
					Self::$variant { source: source.into() }
				}
			}
		)+
	};
}

/// Macro to generate From implementations for error enums with transitive
/// conversions (via pattern).
///
/// This macro handles cases where an error needs to be converted through an
/// intermediate type before being wrapped in the target error enum variant.
///
/// # Example
/// ```rust
/// use utils::impl_source_error_from_via;
///
/// #[derive(Debug)]
/// struct IntermediateError(String);
///
/// impl std::fmt::Display for IntermediateError {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         write!(f, "{}", self.0)
///     }
/// }
///
/// impl std::error::Error for IntermediateError {}
///
/// impl From<std::fmt::Error> for IntermediateError {
///     fn from(_: std::fmt::Error) -> Self {
///         IntermediateError("converted".to_string())
///     }
/// }
///
/// #[derive(Debug)]
/// enum MyError {
///     Intermediate { source: IntermediateError },
/// }
///
/// impl_source_error_from_via!(MyError, {
///     std::fmt::Error => Intermediate via IntermediateError,
/// });
/// ```
#[macro_export]
macro_rules! impl_source_error_from_via {
	($target_error:ty, { $($source_type:ty => $variant:ident via $intermediate_type:ty),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(error: $source_type) -> Self {
					Self::$variant { source: <$intermediate_type>::from(error) }
				}
			}
		)+
	};
}

/// Macro to generate From implementations for error enums with field transformations.
///
/// This macro handles cases where you need to transform the source error into
/// specific fields of the target error variant.
///
/// # Example
/// ```rust
/// use utils::impl_error_from_with_fields;
///
/// #[derive(Debug)]
/// enum MyError {
///     InvalidData { reason: String },
///     ParseError { source: std::num::ParseIntError },
/// }
///
/// impl_error_from_with_fields!(MyError, {
///     std::string::FromUtf8Error => InvalidData { reason: |e: std::string::FromUtf8Error| e.to_string() },
///     std::num::ParseIntError => ParseError { source: |e: std::num::ParseIntError| e },
/// });
/// ```
#[macro_export]
macro_rules! impl_error_from_with_fields {
	($target_error:ty, { $($source_type:ty => $variant:ident { $($field:ident: $transform:expr),+ }),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(source_error: $source_type) -> Self {
					let error_ref = &source_error;
					Self::$variant { $($field: ($transform)(error_ref.clone())),* }
				}
			}
		)+
	};
}

/// Macro to generate From implementations for error enums with plain variants.
///
/// This macro reduces boilerplate when implementing From trait for error types
/// that map to simple enum variants without source fields.
///
/// # Example
/// ```rust
/// use utils::impl_variant_error_from;
///
/// #[derive(Debug)]
/// enum MyError {
///     InvalidUtf8,
///     InvalidFormat,
/// }
///
/// impl_variant_error_from!(MyError, {
///     std::string::FromUtf8Error => InvalidUtf8,
///     std::num::ParseIntError => InvalidFormat,
/// });
/// ```
#[macro_export]
macro_rules! impl_variant_error_from {
	($target_error:ty, { $($source_type:ty => $variant:ident),+ $(,)? }) => {
		$(
			impl From<$source_type> for $target_error {
				fn from(_: $source_type) -> Self {
					Self::$variant
				}
			}
		)+
	};
}

#[cfg(test)]
mod tests {
	use crate::{test_error_from_conversions, test_error_variants};

	// Minimal test error type
	#[derive(Debug)]
	enum TestError {
		#[allow(dead_code)]
		Io {
			source: std::io::Error,
		},
		#[allow(dead_code)]
		Parse {
			source: std::num::ParseIntError,
		},
		Utf8,
		Format,
	}

	impl std::fmt::Display for TestError {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "TestError")
		}
	}

	impl std::error::Error for TestError {}

	impl_source_error_from!(TestError, {
		std::io::Error => Io,
		std::num::ParseIntError => Parse,
	});

	impl_variant_error_from!(TestError, {
		std::string::FromUtf8Error => Utf8,
		std::fmt::Error => Format,
	});

	test_error_from_conversions! {
		test_all_conversions, TestError, [
			std::io::Error::new(std::io::ErrorKind::NotFound, "test"),
			"not_a_number".parse::<i32>().unwrap_err(),
			String::from_utf8(vec![0xff]).unwrap_err(),
			std::fmt::Error,
		]
	}

	// Test via pattern with minimal setup
	#[derive(Debug, PartialEq, Eq)]
	struct SimpleIntermediate(String);

	impl std::fmt::Display for SimpleIntermediate {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "{}", self.0)
		}
	}

	impl std::error::Error for SimpleIntermediate {}

	impl From<std::fmt::Error> for SimpleIntermediate {
		fn from(_: std::fmt::Error) -> Self {
			SimpleIntermediate("converted".to_string())
		}
	}

	test_error_variants! {
		test_error_intermediate, [
			SimpleIntermediate("test".to_string())
		]
	}

	#[derive(Debug)]
	enum ViaTestError {
		#[allow(dead_code)]
		Via { source: SimpleIntermediate },
	}

	impl std::fmt::Display for ViaTestError {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "ViaTestError")
		}
	}

	impl std::error::Error for ViaTestError {}

	impl_source_error_from_via!(ViaTestError, {
		std::fmt::Error => Via via SimpleIntermediate,
	});

	test_error_from_conversions! {
		test_via_conversion, ViaTestError, [
			std::fmt::Error,
		]
	}

	#[derive(Debug)]
	enum FieldTestError {
		#[allow(dead_code)]
		InvalidData { reason: String },
		#[allow(dead_code)]
		ParseFailed { message: String, code: i32 },
	}

	impl std::fmt::Display for FieldTestError {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "FieldTestError")
		}
	}

	impl std::error::Error for FieldTestError {}

	impl_error_from_with_fields!(FieldTestError, {
		std::string::FromUtf8Error => InvalidData { reason: |e: std::string::FromUtf8Error| format!("UTF-8 error: {e}") },
		std::num::ParseIntError => ParseFailed { message: |e: std::num::ParseIntError| e.to_string(), code: |_: std::num::ParseIntError| 42 },
	});

	test_error_from_conversions! {
		test_field_transformations, FieldTestError, [
			String::from_utf8(vec![0xff]).unwrap_err(),
			"not_a_number".parse::<i32>().unwrap_err(),
		]
	}
}
