use rocket::http::Status;

#[get("/live")]
pub fn live() -> Status { Status::Ok }
