//! # Errors
//!
//!
//! ## Overview
//!
//! A collection of our errors for signing client
//!
//! ## Errors
//!
//! - SignedMessageError
//! - Custom IP Error
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

#[allow(dead_code)]
#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum SigningProtocolError {
	Validation(&'static str),
	Subscribing(&'static str),
	Signing(&'static str),
	Other(&'static str),
}
// (&'static str);

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
