//! Handle execution of the signing and DKG protocols
#![allow(dead_code)]
mod context;

pub use entropy_protocol::{
    execute_protocol::{execute_signing_protocol, Channels},
    KeyParams, ProtocolMessage, RecoverableSignature,
};
use kvdb::kv_manager::KvManager;
use sp_core::sr25519;
use subxt::utils::AccountId32;
use synedrion::KeyShare;

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
        let key_share_vec = self
            .kv_manager
            .kv()
            .get(&sign_init.signing_session_info.account_id.to_string())
            .await?;
        let key_share: KeyShare<KeyParams> = kvdb::kv_manager::helpers::deserialize(&key_share_vec)
            .ok_or_else(|| ProtocolErr::Deserialization("Failed to load KeyShare".into()))?;
        Ok(SignContext::new(sign_init, key_share))
    }

    /// handle signing protocol execution.
    #[tracing::instrument(
        skip_all,
        fields(sign_init = ?ctx.sign_init),
        level = tracing::Level::DEBUG
    )]
    pub async fn execute_sign(
        &self,
        ctx: &SignContext,
        channels: Channels,
        threshold_signer: &sr25519::Pair,
        threshold_accounts: Vec<AccountId32>,
    ) -> Result<RecoverableSignature, ProtocolErr> {
        tracing::trace!("Signing context {ctx:?}");

        let rsig = execute_signing_protocol(
            channels,
            &ctx.key_share,
            &ctx.sign_init.signing_session_info.message_hash,
            threshold_signer,
            threshold_accounts,
        )
        .await?;

        let (signature, recovery_id) = rsig.to_backend();
        Ok(RecoverableSignature { signature, recovery_id })
    }
}
