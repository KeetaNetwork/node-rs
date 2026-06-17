#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use snafu::prelude::*;

#[derive(Debug, Snafu)]
pub enum KeetaNetError {
	Internal,
	Unknown { msg: String },
	NotImplemented,
	Code { code: String, message: String },
}
