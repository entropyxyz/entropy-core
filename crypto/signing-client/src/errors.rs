use rocket::response::Responder;

// use crate::IPs;
// use thiserror::Error;

#[derive(Debug)]
pub enum SignedMessageError {
	Missing,
	Invalid,
}

#[derive(Responder)]
#[response(status = 418, content_type = "json")]
pub struct CustomIPError(&'static str);

impl CustomIPError {
	pub fn new(error: &'static str) -> CustomIPError {
		CustomIPError(error)
	}
}

// #[derive(Debug, Clone, Error, Responder)]
// pub enum SigningError {
// 	#[error("initiation of signing protocol failed, IPs not available: {ips:?}")]
// 	InitError { ips: String },
// 	/// Wrap and propagate the tofn error
// 	#[error("execution of signing protocol failed: {e}")]
// 	ExecuteError { e: String },
// 	#[error("result of signing protocol failed: {e}")]
// 	ResultError { e: String },
// }
