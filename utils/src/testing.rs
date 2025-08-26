//! Shared test macros for the node-rs project
//!
//! This module contains reusable test macros that can be used across
//! all crates in the workspace to reduce test code duplication.

/// Macro to generate tests for From conversions on error types.
#[macro_export]
macro_rules! test_error_from_conversions {
	($test_name:ident, $error_type:ty, [$($source_expr:expr),+ $(,)?]) => {
		#[test]
		fn $test_name() {
			let test_cases: &[Box<dyn Fn() -> $error_type>] = &[
				$(Box::new(|| {
					let source_error = $source_expr;
					source_error.into()
				}),)+
			];

			for error_fn in test_cases {
				let error = error_fn();
				let display_str = format!("{}", error);
				let debug_str = format!("{error:?}");
				assert!(!display_str.is_empty());
				assert!(!debug_str.is_empty());
			}
		}
	};
}

/// Macro to generate tests for error variants (Display, Debug, and PartialEq/Eq).
#[macro_export]
macro_rules! test_error_variants {
	($test_name:ident, [$($variant:expr),+ $(,)?]) => {
		#[test]
		fn $test_name() {
			let test_cases = [$($variant),+];

			// Test Display and Debug formatting
			for error in &test_cases {
				let display_str = format!("{}", error);
				let debug_str = format!("{error:?}");
				assert!(!display_str.is_empty());
				assert!(!debug_str.is_empty());
			}

			// Test equality - each error should be equal to itself
			for error in &test_cases {
				assert_eq!(error, error);
			}

			// Test inequality between different variants
			if test_cases.len() > 1 {
				// Compare first error with all others to ensure they're different
				for other in &test_cases[1..] {
					assert_ne!(&test_cases[0], other);
				}
			}
		}
	};
}
#[cfg(test)]
mod tests {
	// Test the macros themselves
	#[derive(Debug, PartialEq, Eq)]
	enum TestError {
		Simple,
		WithData { message: String },
	}

	impl std::fmt::Display for TestError {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			match self {
				TestError::Simple => write!(f, "Simple error"),
				TestError::WithData { message } => write!(f, "Error: {message}"),
			}
		}
	}

	impl std::error::Error for TestError {}

	test_error_variants! {
		test_error_formatting, [
			TestError::Simple,
			TestError::WithData { message: "test".to_string() },
		]
	}

	// Test From conversions (if we had some)
	#[derive(Debug)]
	struct SourceError(&'static str);

	impl std::fmt::Display for SourceError {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "Source: {}", self.0)
		}
	}

	impl std::error::Error for SourceError {}

	impl From<SourceError> for TestError {
		fn from(err: SourceError) -> Self {
			TestError::WithData { message: err.0.to_string() }
		}
	}

	test_error_from_conversions! {
		test_from_conversions, TestError, [
			SourceError("conversion test"),
		]
	}
}
