use crate::IPs;
use rocket::State;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpAddresses {
	pub ip_addresses: Vec<String>
}

#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(
	ip_address: String,
	state: &State<IPs>,

) {
	let shared_data: &IPs = state.inner();
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	if shared_data.current_ips.lock().unwrap().len() < 4 {
		shared_data.current_ips.lock().unwrap().push(ip_address);
	} else {
		// send ips to all addresses
	}
}


#[post("/get_all_ips", format = "json", data = "<ip_addresses>")]
pub async fn get_all_ips(
	ip_addresses: Json<IpAddresses>,
	state: &State<IPs>,

) {
	println!("ip_addresses, {:?}", ip_addresses);
}
