//! protocol runner for the `new_party` api
#![allow(dead_code)]
mod context;
mod signing_message;
pub mod signing_protocol;

use kvdb::kv_manager::KvManager;
use sp_core::crypto::AccountId32;
use subxt::ext::sp_core::sr25519;
use synedrion::{KeyShare, TestSchemeParams};
use tracing::{info, instrument};

pub use self::{context::SignContext, signing_message::SigningMessage, signing_protocol::Channels};
use crate::{
    helpers::signing::{RecoverableSignature, SignatureState},
    sign_init::SignInit,
    signing_client::{SignerState, SigningErr},
};

/// Thin wrapper around `SignerState`, manages execution of a signing party.
#[derive(Clone)]
pub struct ThresholdSigningService<'a> {
    pub state: &'a SignerState,
    pub kv_manager: &'a KvManager,
}

impl std::fmt::Debug for ThresholdSigningService<'_> {
    // skip kv_manager
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSigningService").field("state", &self.state).finish()
    }
}

impl<'a> ThresholdSigningService<'a> {
    pub fn new(state: &'a SignerState, kv_manager: &'a KvManager) -> Self {
        {
            Self { state, kv_manager }
        }
    }

    /// The Sign Context contains all relevant information for protocol execution, and is mostly
    /// stored in the kvdb, and is otherwise provided by the blockchain (`SignInit`).
    #[instrument]
    pub async fn get_sign_context(&self, sign_init: SignInit) -> Result<SignContext, SigningErr> {
        info!("check_sign_init: {sign_init:?}");
        let key_share_vec = self.kv_manager.kv().get(&sign_init.substrate_key).await?;
        let key_share: KeyShare<TestSchemeParams> =
            kvdb::kv_manager::helpers::deserialize(&key_share_vec)
                .ok_or_else(|| SigningErr::Deserialization("Failed to load KeyShare".into()))?;
        Ok(SignContext::new(sign_init, key_share))
    }

    /// handle signing protocol execution.
    #[instrument(skip(channels, threshold_signer))]
    pub async fn execute_sign(
        &self,
        ctx: &SignContext,
        channels: Channels,
        threshold_signer: &sr25519::Pair,
        threshold_accounts: Vec<AccountId32>,
    ) -> Result<RecoverableSignature, SigningErr> {
        info!("execute_sign: {ctx:?}");
        let rsig = signing_protocol::execute_protocol(
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
