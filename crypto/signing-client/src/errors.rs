use rocket::response::Responder;

#[allow(dead_code)]
#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum SigningProtocolError {
	Validation(&'static str),
	Subscribing(&'static str),
	Signing(&'static str),
	Other(&'static str),
}
