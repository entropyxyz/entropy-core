use kvdb::kv_manager::PartyId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(crate = "rocket::serde")]
pub struct SubscribeMessage {
    /// Signing session
    pub session_id: String,
    // TODO: Ideally this should be PartyId,
    // but this requires implementing some Rocket traits for it in `kvdb`
    /// Subscribing party
    pub party_id: String,
}

/// A message sent by subscribing node. Holder struct for subscription-related methods.
impl SubscribeMessage {
    pub fn new(session_id: &str, party_id: PartyId) -> Self {
        Self { session_id: session_id.to_owned(), party_id: party_id.into() }
    }

    pub fn party_id(&self) -> Result<PartyId, String> { self.party_id.clone().try_into() }
}
