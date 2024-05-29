// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Handle execution of the signing and DKG protocols
#![allow(dead_code)]
mod context;

use entropy_kvdb::kv_manager::KvManager;
use entropy_protocol::PartyId;
pub use entropy_protocol::{
    execute_protocol::{execute_signing_protocol, Channels},
    KeyParams, ProtocolMessage, RecoverableSignature, SessionId,
};
use sp_core::sr25519;
use subxt::utils::AccountId32;
use synedrion::{AuxInfo, ThresholdKeyShare};

pub use self::context::SignContext;
use crate::{
    sign_init::SignInit,
    signing_client::{ListenerState, ProtocolErr},
};

/// Thin wrapper around [ListenerState], manages execution of a signing party.
#[derive(Clone)]
pub struct ThresholdSigningService<'a> {
    pub state: &'a ListenerState,
    pub kv_manager: &'a KvManager,
}

impl std::fmt::Debug for ThresholdSigningService<'_> {
    // skip kv_manager
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSigningService").field("state", &self.state).finish()
    }
}

impl<'a> ThresholdSigningService<'a> {
    pub fn new(state: &'a ListenerState, kv_manager: &'a KvManager) -> Self {
        {
            Self { state, kv_manager }
        }
    }

    /// The Sign Context contains all relevant information for protocol execution, and is mostly
    /// stored in the kvdb, and is otherwise provided by the blockchain (`SignInit`).
    #[tracing::instrument(
        skip_all,
        fields(sign_init),
        level = tracing::Level::DEBUG
    )]
    pub async fn get_sign_context(&self, sign_init: SignInit) -> Result<SignContext, ProtocolErr> {
        tracing::debug!("Getting signing context");
        let key_share_and_aux_info_vec = self
            .kv_manager
            .kv()
            .get(&hex::encode(sign_init.signing_session_info.signature_verifying_key.clone()))
            .await?;
        let (key_share, aux_info): (
            ThresholdKeyShare<KeyParams, PartyId>,
            AuxInfo<KeyParams, PartyId>,
        ) = entropy_kvdb::kv_manager::helpers::deserialize(&key_share_and_aux_info_vec)
            .ok_or_else(|| ProtocolErr::Deserialization("Failed to load KeyShare".into()))?;
        Ok(SignContext::new(sign_init, key_share, aux_info))
    }

    /// handle signing protocol execution.
    #[tracing::instrument(
        skip_all,
        level = tracing::Level::DEBUG
    )]
    pub async fn execute_sign(
        &self,
        session_id: SessionId,
        key_share: &ThresholdKeyShare<KeyParams, PartyId>,
        aux_info: &AuxInfo<KeyParams, PartyId>,
        channels: Channels,
        threshold_signer: &sr25519::Pair,
        threshold_accounts: Vec<AccountId32>,
    ) -> Result<RecoverableSignature, ProtocolErr> {
        tracing::trace!("Signing info {session_id:?}");

        let message_hash = if let SessionId::Sign(session_info) = &session_id {
            session_info.message_hash
        } else {
            return Err(ProtocolErr::BadSessionId);
        };

        let rsig = execute_signing_protocol(
            session_id,
            channels,
            &key_share,
            aux_info,
            &message_hash,
            threshold_signer,
            threshold_accounts,
        )
        .await?;

        let (signature, recovery_id) = rsig.to_backend();
        Ok(RecoverableSignature { signature, recovery_id })
    }
}
