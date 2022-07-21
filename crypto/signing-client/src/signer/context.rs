//! Context and helper types
#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tofn::{
	collections::{Subset, TypedUsize},
	gg20::{
		keygen::{GroupPublicInfo, KeygenPartyId, SecretKeyShare, ShareSecretInfo},
		sign::SignParties,
	},
};
use tofnd::TofndResult;
use tokio::sync::mpsc;

pub(crate) type MessageDigest = tofn::gg20::sign::MessageDigest;

/// An unchecked SignInit Message
#[derive(Clone, Debug)]
pub(crate) struct SignInitUnchecked {
	pub(crate) new_sig_uid: String, // this is only used for logging
	pub(crate) key_uid: String,
	pub(crate) participant_uids: Vec<String>,
	pub(crate) participant_indices: Vec<usize>,
	pub(crate) message_to_sign: MessageDigest,
}

/// A sanitized SignInit Message
#[derive(Clone, Debug)]
pub(crate) struct SignInitSanitized {
	pub(crate) new_sig_uid: String, // this is only used for logging
	// pub(crate) key_uid: String,
	pub(crate) participant_uids: Vec<String>,
	pub(crate) participant_indices: Vec<usize>,
	pub(crate) message_to_sign: MessageDigest,
}

/// Context for the signing protocol
#[derive(Clone, Debug)]
pub(crate) struct Context {
	pub(crate) sign_init: SignInitSanitized,
	pub(crate) party_info: PartyInfo,
	pub(crate) sign_share_counts: Vec<usize>,
	pub(crate) tofnd_subindex: usize,
	pub(crate) share: ShareSecretInfo,
	pub(crate) sign_parties: Subset<KeygenPartyId>,
}

/// Struct to hold `tonfd` info. This consists of information we need to
/// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TofndInfo {
	pub(crate) party_uids: Vec<String>,
	pub(crate) share_counts: Vec<usize>,
	pub(crate) index: usize,
}

/// `KeyShareKv` record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
	pub(crate) common: GroupPublicInfo,
	pub(crate) shares: Vec<ShareSecretInfo>,
	pub(crate) tofnd: TofndInfo,
}

/// define the input and output channels of generic execute_protocol worker
pub(crate) struct ProtocolCommunication<InMsg, OutMsg> {
	pub(crate) receiver: mpsc::UnboundedReceiver<InMsg>,
	pub(crate) sender: mpsc::UnboundedSender<OutMsg>,
}
impl<InMsg, OutMsg> ProtocolCommunication<InMsg, OutMsg> {
	pub fn new(
		receiver: mpsc::UnboundedReceiver<InMsg>,
		sender: mpsc::UnboundedSender<OutMsg>,
	) -> Self {
		Self { receiver, sender }
	}
}

impl PartyInfo {
	/// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
	/// Also needed in recovery
	pub(crate) fn get_party_info(
		secret_key_shares: Vec<SecretKeyShare>,
		uids: Vec<String>,
		share_counts: Vec<usize>,
		tofnd_index: usize,
	) -> Self {
		// grap the first share to acquire common data
		let common = secret_key_shares[0].group().clone();

		// aggregate share data into a vector
		let shares = secret_key_shares.into_iter().map(|share| share.share().clone()).collect();

		// add tofnd data
		let tofnd = TofndInfo { party_uids: uids, share_counts, index: tofnd_index };

		PartyInfo { common, shares, tofnd }
	}
}

impl Context {
	/// create a new signing context
	pub(crate) fn new(
		sign_init: SignInitSanitized,
		party_info: PartyInfo,
		tofnd_subindex: usize,
	) -> TofndResult<Self> {
		// retrieve sign_share_couts and secret_key_shares here instead of adding
		// getters to immediatelly dicover potential errors
		let sign_share_counts = Self::get_sign_share_counts(
			&party_info.tofnd.party_uids,
			&party_info.tofnd.share_counts,
			&sign_init.participant_uids,
		)?;

		let sign_parties = Self::get_sign_parties(
			party_info.tofnd.party_uids.len(),
			&sign_init.participant_indices,
		)?;

		let share = Self::get_share(&party_info, tofnd_subindex)?;
		Ok(Self { sign_init, party_info, sign_share_counts, tofnd_subindex, share, sign_parties })
	}

	pub(crate) fn group(&self) -> &GroupPublicInfo {
		&self.party_info.common
	}

	/// from keygen we have
	///  party uids:         [A, B, C, D]
	///  share counts:       [1, 2, 3, 4]
	/// in sign we receive
	///  sign uids:          [D, B]
	/// we need to construct an array of share counts that is alligned with sign uids
	///  sign share counts:  [4, 2]
	fn get_sign_share_counts(
		keygen_uids: &[String],
		keygen_share_counts: &[usize],
		sign_uids: &[String],
	) -> TofndResult<Vec<usize>> {
		if keygen_uids.len() != keygen_share_counts.len() {
			return Err(anyhow!("misalligned keygen uids and keygen share counts"))
		}
		let mut sign_share_counts = vec![];
		for sign_uid in sign_uids {
			let keygen_index = keygen_uids
				.iter()
				.position(|uid| uid == sign_uid)
				.ok_or_else(|| anyhow!("Sign uid was not found"))?;
			let sign_share_count =
				*keygen_share_counts.get(keygen_index).ok_or_else(|| anyhow!("invalid index"))?;
			sign_share_counts.push(sign_share_count);
		}
		Ok(sign_share_counts)
	}

	fn get_share(party_info: &PartyInfo, tofnd_subindex: usize) -> TofndResult<ShareSecretInfo> {
		Ok(party_info
			.shares
			.get(tofnd_subindex)
			.ok_or_else(|| anyhow!("failed to get ShareSecretInfo from PartyInfo"))?
			.clone())
	}

	pub(crate) fn msg_to_sign(&self) -> &MessageDigest {
		&self.sign_init.message_to_sign
	}

	/// create a `Subset` of sign parties
	/// Example:
	/// from keygen init we have:
	///   keygen_party_uids:    [a, b, c, d]
	///   keygen_party_indices: [0, 1, 2, 3]
	/// from sign init we have:
	///   sign_party_uids:      [d, b]
	///   sign_party_indices:   [3, 1]
	/// result:
	///   sign_parties:         [None      -> party a with index 0 is not a signer
	///                          Some(())  -> party b with index 1 is a signer
	///                          None      -> party c with index 2 is not a signer
	///                          Some(())] -> party d with index 3 is a signer
	pub(crate) fn get_sign_parties(
		length: usize,
		sign_indices: &[usize],
	) -> TofndResult<SignParties> {
		let mut sign_parties = Subset::with_max_size(length);
		for signer_idx in sign_indices.iter() {
			if sign_parties.add(TypedUsize::from_usize(*signer_idx)).is_err() {
				return Err(anyhow!("failed to call Subset::add"))
			}
		}
		Ok(sign_parties)
	}

	/// get signers' uids with respect to keygen uids ordering
	/// Example:
	/// from keygen init we have:
	///   keygen_party_uids:    [a, b, c, d]
	/// from sign init we have:
	///   sign_party_uids:      [d, c, a]
	/// result:
	///   sign_parties:         [a, c, d]
	pub(crate) fn sign_uids(&self) -> Vec<String> {
		let mut sign_uids = vec![];
		for uid in self.party_info.tofnd.party_uids.iter() {
			if self.sign_init.participant_uids.iter().any(|s_uid| s_uid == uid) {
				sign_uids.push(uid.clone());
			}
		}
		sign_uids
	}
}
