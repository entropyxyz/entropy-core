use crate::{sign::provide_share, store_share::store_keyshare};
use rocket::routes;
use serde::Deserialize;
use std::env;

#[macro_use]
extern crate rocket;

use rocket::State;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod utils;

mod com_manager;
mod sign;
mod store_share;

use com_manager::{broadcast, issue_idx, subscribe, Db};
// ToDo: JA add proper response types and formalize them across all endpoints

#[derive(Debug, Clone)]
pub struct Global {
    mnemonic: String
}

#[derive(Deserialize, Debug)]
struct Configuration {
	MNEMONIC: String
}

#[launch]
fn rocket() -> _ {

	let c = load_environment_variables();

	let global = Global {
        mnemonic: c.MNEMONIC.to_string()
    };
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
		.manage(global)

}


fn load_environment_variables() -> Configuration {
	let c;

    if cfg!(test) {
        c = Configuration {
			MNEMONIC: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click".to_string()
		}
    } else {
		c = envy::from_env::<Configuration>()
        	.expect("Please provide MNEMONIC as env var");
	}
	c
}
