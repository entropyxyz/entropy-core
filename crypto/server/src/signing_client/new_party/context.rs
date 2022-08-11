use kvdb::kv_manager::value::PartyInfo;
use tofn::{
  collections::Subset,
  gg20::keygen::{GroupPublicInfo, KeygenPartyId, ShareSecretInfo},
  multisig::sign::MessageDigest,
};

use crate::sign_init::SignInit;

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/types.rs#L30
/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
  pub sign_init:         SignInit,
  pub party_info:        PartyInfo,
  pub share:             ShareSecretInfo,
  pub sign_parties:      Subset<KeygenPartyId>,
  // note, tofnd needs this, we don't
  pub sign_share_counts: Vec<usize>,
  // note, tofnd needs this, we don't
  // pub tofnd_subindex: usize,
}

impl SignContext {
  #[allow(dead_code)]
  pub fn new(sign_init: SignInit, party_info: PartyInfo) -> Self {
    {
      todo!()
      // Self { sign_init, party_info, share: todo!(), sign_parties: todo!() }
    }
  }

  pub fn group(&self) -> &GroupPublicInfo { todo!() }

  pub fn msg_to_sign(&self) -> &MessageDigest { todo!() }

  pub fn sign_uids(&self) -> &[String] { todo!() }
}
