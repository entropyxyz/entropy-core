use serde::{Deserialize, Serialize};
use tofn::{
  collections::Subset,
  gg20::keygen::{GroupPublicInfo, KeygenPartyId, SecretKeyShare, ShareSecretInfo},
};

use super::sign_init::SignInit;

#[derive(Debug, Clone)]
pub struct SignContext {
  pub sign_init:    SignInit,
  pub party_info:   PartyInfo,
  pub share:        ShareSecretInfo,
  // todo: Not sure what this is
  pub sign_parties: Subset<KeygenPartyId>,
  // pub sign_share_counts: Vec<usize>, // note, tofnd needs this, we don't
  // pub tofnd_subindex: usize, // note, tofnd needs this, we don't
}

impl SignContext {
  #[allow(dead_code)]
  pub fn new(sign_init: SignInit, party_info: PartyInfo) -> Self {
    {
      todo!()
      // Self { sign_init, party_info, share: todo!(), sign_parties: todo!() }
    }
  }
}

// placeholder
#[derive(Debug, Clone)]
pub struct PartyInfo {
  pub common: GroupPublicInfo,
  pub shares: Vec<ShareSecretInfo>,
  pub tofnd:  TofndInfo,
}

/// Struct to hold `tonfd` info. This consists of information we need to
/// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofndInfo {
  pub party_uids:   Vec<String>,
  pub share_counts: Vec<usize>,
  pub index:        usize,
}
