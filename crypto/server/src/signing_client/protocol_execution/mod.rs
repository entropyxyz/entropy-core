//! Handle execution of the signing and DKG protocols
#![allow(dead_code)]
mod context;

pub use entropy_protocol::{
    execute_protocol::{execute_signing_protocol, Channels},
    KeyParams, ProtocolMessage, RecoverableSignature,
};
use kvdb::kv_manager::KvManager;
use subxt::utils::AccountId32;
use synedrion::KeyShare;
use tracing::{info, instrument};

pub use self::context::SignContext;
use crate::{
    helpers::signing::SignatureState,
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
    #[instrument]
    pub async fn get_sign_context(&self, sign_init: SignInit) -> Result<SignContext, ProtocolErr> {
        info!("check_sign_init: {sign_init:?}");
        let key_share_vec = self.kv_manager.kv().get(&sign_init.substrate_key).await?;
        let key_share: KeyShare<KeyParams> = kvdb::kv_manager::helpers::deserialize(&key_share_vec)
            .ok_or_else(|| ProtocolErr::Deserialization("Failed to load KeyShare".into()))?;
        Ok(SignContext::new(sign_init, key_share))
    }

    /// handle signing protocol execution.
    #[instrument(skip(channels, threshold_signer))]
    pub async fn execute_sign(
        &self,
        ctx: &SignContext,
        channels: Channels,
        threshold_signer: &subxt_signer::sr25519::Keypair,
        threshold_accounts: Vec<AccountId32>,
    ) -> Result<RecoverableSignature, ProtocolErr> {
        info!("execute_sign: {ctx:?}");
        let rsig = execute_signing_protocol(
            channels,
            &ctx.key_share,
            &ctx.sign_init.msg,
            threshold_signer,
            threshold_accounts,
        )
        .await?;

        let (signature, recovery_id) = rsig.to_backend();
        Ok(RecoverableSignature { signature, recovery_id })
    }

    // todo placeholder for any result handling
    #[instrument]
    #[allow(unused_variables)]
    pub fn handle_result(
        &self,
        signature: &RecoverableSignature,
        sig_hash: &[u8],
        signatures: &SignatureState,
    ) {
        signatures.insert(sig_hash, signature);
    }
}
