use crate::{sign::provide_share, store_share::store_keyshare};
use rocket::routes;

#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod utils;

mod com_manager;
mod sign;
mod store_share;

use com_manager::{broadcast, issue_idx, subscribe, Db};
// ToDo: JA add proper response types and formalize them across all endpoints

#[launch]
fn rocket() -> _ {
	rocket::build()
		.mount(
			"/",
			routes![
				store_keyshare,
				// for testing, we let node1 not provede a share
				provide_share,
				subscribe,
				issue_idx,
				broadcast
			],
		)
		.manage(Db::empty())
}
