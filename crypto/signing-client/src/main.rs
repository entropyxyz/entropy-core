use crate::store_share::store_keyshare;
use crate::sign::provide_share;
use crate::com_manager::start_com_manager;
use rocket::{routes};

#[macro_use]
extern crate rocket;

mod store_share;
mod com_manager;
mod sign;

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![
        store_keyshare,
        provide_share,
        start_com_manager, 
        ])
}
