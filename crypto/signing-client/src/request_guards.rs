//! # Request Guards
//!
//!
//! ## Overview
//!
//! A collection of our request guards for signing client
//!
//! ## Guards
//!
//! - signed-message - requiers signed message in header (not implemented)
use crate::errors::SignedMessageError;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Outcome, Request};

pub struct SignedMessage<'r>(&'r str);

/// Is it a valid signature (not implemented)
pub fn is_valid(signature: &str) -> bool {
	true
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SignedMessage<'r> {
	type Error = SignedMessageError;

	async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
		match req.headers().get_one("signed-message") {
			None => Outcome::Failure((Status::BadRequest, SignedMessageError::Missing)),
			Some(message) if is_valid(message) => Outcome::Success(SignedMessage(message)),
			Some(_) => Outcome::Failure((Status::BadRequest, SignedMessageError::Invalid)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn is_valid_test() {
		assert_eq!(is_valid("test"), true);
	}
}
