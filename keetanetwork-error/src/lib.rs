use snafu::prelude::*;

#[derive(Debug, Snafu)]
pub enum KeetaNetError {
	Internal,
	Unknown { msg: String },
	NotImplemented,
	Code { code: String, message: String },
}
