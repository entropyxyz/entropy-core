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
	#[allow(dead_code)]
	pub fn new(error: &'static str) -> CustomIPError {
		CustomIPError(error)
	}
}
