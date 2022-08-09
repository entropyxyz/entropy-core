use std::sync::Mutex;

use crate::PartyUid;

pub mod api;
pub mod deprecating_sign;
pub mod errors;
pub mod handle_signing;
pub mod request_guards;
#[cfg(test)]
mod tests;

/// holds KVDB instance, threshold mnemonic and endpoint of running node
#[derive(Debug, Default)]
pub struct CommunicationManagerState {
	/// Generate unique ids for each signing party
	// TODO(TK): be more robust than a counter
	party_id_nonce: Mutex<usize>,
	// TODO(TK): what does this do that kv_manager doesn't do?
	current_ips: Mutex<Vec<String>>,
}

impl CommunicationManagerState {
	#[allow(dead_code)]
	pub(crate) fn get_next_party_id(&self) -> PartyUid {
		let mut nonce = *self.party_id_nonce.lock().unwrap();
		nonce += 1;
		nonce
	}
}
