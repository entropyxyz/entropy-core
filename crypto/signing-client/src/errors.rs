use rocket::response::Responder;

#[derive(Debug)]
pub enum SignedMessageError {
	Missing,
	Invalid,
}


#[derive(Responder)]
#[response(status = 418, content_type = "json")]
pub struct CustomError(&'static str);

impl CustomError {
	pub fn new(error: &'static str) -> CustomError {
		CustomError(error)
	}
}
