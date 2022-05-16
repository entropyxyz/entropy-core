use rocket::http::Status;
use rocket::request::{self, Outcome, Request, FromRequest};
use crate::errors::SignedMessageError;

struct SignedMessage<'r>(&'r str);

fn is_valid(signature: &str) -> bool {
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
