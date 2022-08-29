use kvdb::kv_manager::value::PartyInfo;
use tofn::{
    collections::Subset,
    gg20::{
        keygen::{GroupPublicInfo, KeygenPartyId, ShareSecretInfo},
        sign::SignParties,
    },
    multisig::sign::MessageDigest,
};

use crate::sign_init::SignInit;

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/types.rs#L30
/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
    /// Party context from the Communication Manager
    pub sign_init: SignInit,
    /// Info stored in the kvdb
    pub party_info: PartyInfo,
    /// secret key share, overlaps party_info
    pub share: ShareSecretInfo,
    /// The set of parties participating in the protocol
    pub sign_parties: Subset<KeygenPartyId>,
    // irrelevant, always Vec[1]. If this node had weight to each share, and or more than one
    // shares, this would be the weights of each share at each index.
    pub sign_share_counts: Vec<usize>,
    // irrelevant, always 0. If this node holds N>1 shares, this value would lie in [0, N-1].
    pub tofnd_subindex: usize,
}

impl SignContext {
    #[allow(dead_code)]
    pub fn new(sign_init: SignInit, party_info: PartyInfo) -> Self {
        let share = party_info.shares.get(0).expect("secret share vec corrupted").clone();
        let sign_parties = SignContext::get_sign_parties(2, &sign_init.signer_idxs).unwrap();
        Self {
            sign_init,
            party_info,
            share,
            sign_parties,
            sign_share_counts: vec![1],
            tofnd_subindex: 0,
        }
    }

    pub(super) fn get_sign_parties(
        length: usize,
        sign_indices: &[usize],
    ) -> anyhow::Result<SignParties> {
        let mut sign_parties = Subset::with_max_size(length);
        for signer_idx in sign_indices.iter() {
            if let Err(e) = sign_parties.add(tofn::collections::TypedUsize::from_usize(*signer_idx))
            {
                return Err(anyhow::anyhow!("failed to call Subset::add: {:?}", e));
            }
        }
        Ok(sign_parties)
    }

    pub fn group(&self) -> &GroupPublicInfo { &self.party_info.common }

    pub fn msg_to_sign(&self) -> &MessageDigest { &self.sign_init.msg }

    // TODO(TK):  unclear whether this method is correctly implemented. The upstream version takes
    // the intersection of self.party_info.tofnd.party_uids and self.sign_init.participant_uids.
    //
    //
    // https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/types.rs#L152
    // Ex:
    // keygen_party_uids: [a,b,c,d]
    // sign_party_uids: [d,c,a]
    // result: [a,c,d]
    pub fn sign_uids(&self) -> Vec<String> {
        let a = self.sign_init.signer_uids.clone();
        let b = self.party_info.tofnd.party_uids.clone();
        info!(
            "temporary log. got participant_uids: {:?};\ngot party_uids: {:?}",
            self.sign_init.signer_uids.clone(),
            self.party_info.tofnd.party_uids.clone()
        );
        assert_eq!(a, b);
        a
        // self
        //   .party_info
        //   .tofnd
        //   .party_uids
        //   .iter()
        //   .filter_map(|uid| {
        //     let pred = true;
        //     if pred {
        //       // self.sign_parties.contains(uid) {
        //       Some(uid.clone())
        //     } else {
        //       None
        //     }
        //   })
        //   .collect::<Vec<_>>()
    }
}
