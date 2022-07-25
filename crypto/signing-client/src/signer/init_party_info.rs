use crate::{Global, PartyId};
use serde::{Deserialize, Serialize};

/// Information passed from the Communication Manager to all nodes on SigningParty Initialization.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InitPartyInfo {
	pub party_id: PartyId,
	pub ip_addresses: Vec<String>,
}

impl InitPartyInfo {
	pub(crate) fn new(global: &Global, ip_addresses: Vec<String>) -> Self {
		let party_id = {
			let mut party_id = *global.party_id_nonce.lock().unwrap();
			party_id += 1;
			party_id
		};
		Self { party_id, ip_addresses }
	}
}
