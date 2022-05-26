use crate::IPs;
use rocket::State;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpAddresses {
	pub address_alice: String,
	pub address_1: String,
	pub address_2: String,
	pub address_3: String,
	pub address_4: String,
	pub address_5: String,
}

#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(
	ip_address: String,
	state: &State<IPs>,

) {
	let shared_data: &IPs = state.inner();
    shared_data.current_ips.lock().unwrap().push(ip_address);
}


#[post("/get_all_ips", format = "json", data = "<ip_addresses>")]
pub async fn get_all_ips(
	ip_addresses: Json<IpAddresses>,
	state: &State<IPs>,

) {

}
