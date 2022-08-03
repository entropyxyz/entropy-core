use crate::PartyUid;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Information passed from the Communication Manager to all nodes on `ProtocolManager`
/// Initialization.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InitPartyInfo {
	/// Unique id of this signature (may be repeated if this party fails)
	pub sig_uid: Uuid,
	/// Unique id of user's key (for retreival from kv-store)
	pub key_uid: Uuid,
	/// Unique id of this signing party
	pub party_uid: PartyUid,
	/// IP addresses of each node in the party
	pub ip_addresses: Vec<String>,
	/// Hash of the message to sign
	pub msg: String,
}

impl InitPartyInfo {
	// todo: replace &Global with tighter scope
	pub(crate) fn new(
		party_uid: PartyUid,
		ip_addresses: Vec<String>,
		key_uid: Uuid,
		msg: String,
		repeated_sig_uid: Option<Uuid>,
	) -> Self {
		let sig_uid = if let Some(uid) = repeated_sig_uid { uid } else { Uuid::new_v4() };
		Self { party_uid, ip_addresses, sig_uid, key_uid, msg }
	}

	pub(crate) fn sanitize(self) -> anyhow::Result<SanitizedPartyInfo> {
		Ok(SanitizedPartyInfo(self))
	}
}

/// Wrapper around `InitPartyInfo` to return after sanity checks
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SanitizedPartyInfo(pub(crate) InitPartyInfo);
