use rocket::http::Status;

#[get("/healthz")]
pub fn healthz() -> Status { Status::Ok }
