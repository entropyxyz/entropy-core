use crate::{com_manager::start_com_manager, sign::provide_share, store_share::store_keyshare};
use rocket::routes;

#[macro_use]
extern crate rocket;

mod com_manager;
mod sign;
mod store_share;


use com_manager::{subscribe, issue_idx, broadcast};
// ToDo: JA add proper response types and formalize them across all endpoints

#[launch]
fn rocket() -> _ {
	rocket::build().mount("/", routes![
		store_keyshare, 
		provide_share, 
		start_com_manager,
		subscribe, issue_idx, broadcast])
}
