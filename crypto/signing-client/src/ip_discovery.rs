use crate::IPs;
use reqwest;
use rocket::serde::json::Json;
use rocket::{
	http::{ContentType, Status},
	State, response::status
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use crate::errors::CustomIPError;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpAddresses {
	pub ip_addresses: Vec<String>,
}

#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(ip_address: String, state: &State<IPs>) -> Result<Status, CustomIPError> {
	let shared_data: &IPs = state.inner();
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	let does_contain = shared_data.current_ips.lock().unwrap().contains(&ip_address);
	if does_contain {
		return Err(CustomIPError::new("Duplicate IP"))
	}
	if shared_data.current_ips.lock().unwrap().len() < 4 {
		shared_data.current_ips.lock().unwrap().push(ip_address);
		Ok(Status::Ok)
	} else {
		shared_data.current_ips.lock().unwrap().push(ip_address);
		let all_ip_vec = shared_data.current_ips.lock().unwrap().to_vec();
		let all_ips = IpAddresses { ip_addresses: all_ip_vec.clone() };
		for ip in all_ip_vec.clone() {
			let client = reqwest::Client::new();
			let route = "/get_all_ips";
			let mut full_route = "http://".to_owned();
			full_route.push_str(&ip);
			full_route.push_str(route);
			let res = client
				.post(full_route)
				.header("Content-Type", "application/json")
				.json(&all_ips.clone())
				.send()
				.await
				.unwrap();
		}
		Ok(Status::Ok)
	}
}

#[post("/get_all_ips", format = "json", data = "<ip_addresses>")]
pub async fn get_all_ips(ip_addresses: Json<IpAddresses>, state: &State<IPs>) {
	println!("ip_addresses, {:?}", ip_addresses);
	// send straight to GRPC to start signing
}
