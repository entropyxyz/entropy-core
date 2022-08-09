pub mod api;
pub mod deprecating_sign;
mod errors;
mod handle_signing;
mod request_guards;
#[cfg(test)] mod tests;

use std::{collections::HashMap, sync::Mutex};

use crate::PartyUid;

/// holds KVDB instance, threshold mnemonic and endpoint of running node
#[derive(Debug, Default)]
pub struct CommunicationManagerState {
  /// Generate unique ids for each signing party
  // TODO(TK): be more robust than a counter
  party_id_nonce: Mutex<usize>,
  // Mapping maintained by the CM: Node IP -> Share index
  // Nodes inform the CM of the share index they hold by calling `inform_share_index`
  #[allow(dead_code)]
  current_ips:    Mutex<HashMap<String, usize>>,
}

impl CommunicationManagerState {
  #[allow(dead_code)]
  pub(crate) fn get_next_party_id(&self) -> PartyUid {
    let mut nonce = *self.party_id_nonce.lock().unwrap();
    nonce += 1;
    nonce
  }
}
