use kvdb::kv_manager::value::PartyInfo;
use tofn::{
    collections::Subset,
    gg20::{
        keygen::{GroupPublicInfo, KeygenPartyId, ShareSecretInfo},
        sign::SignParties,
    },
    multisig::sign::MessageDigest,
};

use crate::{sign_init::SignInit, signing_client::SigningErr};

/// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/types.rs#L30
/// Context for Signing Protocol execution.
#[derive(Debug, Clone)]
pub struct SignContext {
    /// Party context from block proposer
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
    pub fn new(sign_init: SignInit, party_info: PartyInfo) -> Result<Self, SigningErr> {
        let share = party_info.shares.get(0).expect("secret share vec corrupted").clone();
        let sign_parties = SignContext::get_sign_parties(2, &sign_init.signer_idxs)?;
        Ok(Self {
            sign_init,
            party_info,
            share,
            sign_parties,
            sign_share_counts: vec![1],
            tofnd_subindex: 0,
        })
    }

    pub(super) fn get_sign_parties(
        length: usize,
        sign_indices: &[usize],
    ) -> anyhow::Result<SignParties> {
        let mut sign_parties = Subset::with_max_size(length);
        for signer_idx in sign_indices.iter() {
            sign_parties
                .add(tofn::collections::TypedUsize::from_usize(*signer_idx))
                .map_err(|err| anyhow::anyhow!("failed to call Subset::add: {:?}", err))?;
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
        // TODO: why do we have two datastructures with seemingly identical contents?
        // It's a potential source of errors.
        assert_eq!(&self.sign_init.signer_uids, &self.party_info.tofnd.party_uids);
        self.sign_init
            .signer_uids
            .iter()
            .zip(self.sign_init.signer_idxs.iter())
            .filter_map(|(uid, idx)| {
                if self
                    .sign_parties
                    .iter()
                    .any(|s_idx| s_idx == tofn::collections::TypedUsize::from_usize(*idx))
                {
                    Some(uid.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }
}
