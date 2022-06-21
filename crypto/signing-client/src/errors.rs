use rocket::response::Responder;

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
