//! Text for errors, attributes and logs, without Rust's formatting
//! machinery.
//!
//! `format!` and `Display` pull in `core::fmt`: about 30 KB of every
//! contract, paid for on every deploy. Contracts build their messages from
//! pieces instead, with [`text!`](crate::text!) (and [`bail!`](crate::bail!)
//! and [`ensure!`](crate::ensure!), which use it):
//!
//! ```ignore
//! ensure!(paid, "attach exactly ", config.food_price, " of the food token");
//! attribute("fullness", pet.fullness);
//! log(&text!("fed ", meals, " times"));
//! ```
//!
//! Strings, integers, `bool` and `char` are [`Text`]; implement it for
//! your own types to use them as pieces.

/// A value that writes itself as text: a piece of a [`text!`](crate::text!).
pub trait Text {
	/// Append this value's text to `out`.
	fn write_text(&self, out: &mut String);
}

impl Text for str {
	fn write_text(&self, out: &mut String) {
		out.push_str(self);
	}
}

impl Text for String {
	fn write_text(&self, out: &mut String) {
		out.push_str(self);
	}
}

impl<T: Text + ?Sized> Text for &T {
	fn write_text(&self, out: &mut String) {
		(**self).write_text(out);
	}
}

impl Text for bool {
	fn write_text(&self, out: &mut String) {
		out.push_str(if *self {
			"true"
		} else {
			"false"
		});
	}
}

impl Text for char {
	fn write_text(&self, out: &mut String) {
		out.push(*self);
	}
}

macro_rules! integers {
	($signed:literal: $($ty:ty),*) => {$(
		impl Text for $ty {
			fn write_text(&self, out: &mut String) {
				write_decimal(out, *self as i128 as u128, $signed);
			}
		}
	)*};
}

integers!(false: u8, u16, u32, u64, usize, u128);
integers!(true: i8, i16, i32, i64, isize, i128);

/// An integer in decimal: `value`, read as an `i128` if `signed`. On-chain
/// the engine writes it ([`crate::abi::syscall::DECIMAL`]), so contracts
/// carry no number-printing code.
#[cfg(target_os = "solana")]
#[inline(never)]
#[allow(unsafe_code)]
fn write_decimal(out: &mut String, value: u128, signed: bool) {
	let mut digits = [0u8; crate::abi::MAX_DECIMAL];
	let bytes = value.to_le_bytes();
	// SAFETY: `bytes` is 16 bytes; `digits` has room for MAX_DECIMAL.
	let len = unsafe { crate::sys::keeta_decimal(bytes.as_ptr(), signed as u64, digits.as_mut_ptr()) } as usize;
	// SAFETY: the engine writes ASCII digits and '-' only, so valid UTF-8.
	out.push_str(unsafe { core::str::from_utf8_unchecked(&digits[..len.min(digits.len())]) });
}

#[cfg(not(target_os = "solana"))]
fn write_decimal(out: &mut String, value: u128, signed: bool) {
	if signed {
		out.push_str(&(value as i128).to_string());
	} else {
		out.push_str(&value.to_string());
	}
}

/// Whether `text` has a `{`: a sign of a `format!`-style message, which
/// [`bail!`](crate::bail!) does not format.
#[doc(hidden)]
pub const fn has_brace(text: &str) -> bool {
	let bytes = text.as_bytes();
	let mut index = 0;
	while index < bytes.len() {
		if bytes[index] == b'{' {
			return true;
		}
		index += 1;
	}
	false
}

/// Text made of pieces, each a [`Text`]: `text!("fed ", meals, " times")`.
#[macro_export]
macro_rules! text {
	($($piece:expr),* $(,)?) => {{
		let mut out = ::std::string::String::new();
		$( $crate::Text::write_text(&$piece, &mut out); )*
		out
	}};
}

#[cfg(test)]
mod tests {
	use super::*;

	fn text(value: impl Text) -> String {
		let mut out = String::new();
		value.write_text(&mut out);
		out
	}

	#[test]
	fn writes_integers_as_display_does() {
		for value in [
			0u128,
			7,
			10,
			999_999_999,
			1_000_000_000,
			u64::MAX as u128,
			u64::MAX as u128 + 1,
			10u128.pow(27),
			u128::MAX,
		] {
			assert_eq!(text(value), value.to_string());
		}
		for value in [0i128, -1, i128::MIN, i128::MAX, -(10i128.pow(20))] {
			assert_eq!(text(value), value.to_string());
		}
		for value in [0i64, -5, i64::MIN, i64::MAX] {
			assert_eq!(text(value), value.to_string());
		}
		assert_eq!(text(u64::MAX), u64::MAX.to_string());
		assert_eq!(text(-3i8), "-3");
	}

	#[test]
	fn joins_pieces() {
		let name = String::from("Pixel");
		assert_eq!(crate::text!("fed ", name, " ", 3u64, " times: ", true, '!'), "fed Pixel 3 times: true!");
		assert!(has_brace("a {name}"));
		assert!(!has_brace("plain"));
	}
}
