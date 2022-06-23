use rocket::response::Responder;

use crate::IPs;
use thiserror::Error;

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

#[derive(Debug, Clone,Error, Responder)]
pub enum SigningProtocolError {
	#[error("initiation of signing protocol failed, IPs not available: {ips:?}")]
	SigningInitError { ips: IPs },
	/// Wrap and propagate the tofn error
	#[error("execution of signing protocol failed: {e}")]
	SigningExecuteError{e: String},
	#[error("result of signing protocol failed: {e}")]
	SigningResultError{e: String},
}
