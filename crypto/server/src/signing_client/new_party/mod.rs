//! protocol runner for the `new_party` api
#![allow(dead_code)]
mod context;
mod signing_message;
mod tofn_protocol;
use bincode::Options;
use kvdb::kv_manager::{value::PartyInfo, KvManager};
use tofn::{
    collections::TypedUsize,
    gg20,
    gg20::keygen::{KeygenShareId, SecretKeyShare},
    sdk::api::{to_recoverable_signature, RecoverableSignature},
};
use tracing::{info, instrument};

pub use self::{context::SignContext, signing_message::SigningMessage, tofn_protocol::Channels};
use crate::{
    helpers::signing::SignatureState,
    sign_init::SignInit,
    signing_client::{SignerState, SigningErr},
};

/// corresponds to https://github.com/axelarnetwork/tofnd/blob/0a70c4bb8c86b26804f59d0921dcd3235e85fdc0/src/gg20/service/mod.rs#L12
/// Thin wrapper around `SignerState`, manages execution of a signing party.
#[derive(Clone)]
pub struct Gg20Service<'a> {
    pub state: &'a SignerState,
    pub kv_manager: &'a KvManager,
}

impl std::fmt::Debug for Gg20Service<'_> {
    // skip kv_manager
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gg20Service").field("state", &self.state).finish()
    }
}

impl<'a> Gg20Service<'a> {
    pub fn new(state: &'a SignerState, kv_manager: &'a KvManager) -> Self {
        {
            Self { state, kv_manager }
        }
    }

    /// The Sign Context contains all relevant information for protocol execution, and is mostly
    /// stored in the kvdb, and is otherwise provided by the CM (`SignInit`).
    #[instrument]
    pub async fn get_sign_context(&self, sign_init: SignInit) -> Result<SignContext, SigningErr> {
        info!("check_sign_init: {sign_init:?}");
        println!("check_sign_init: {sign_init:?}");
        let party_vec = self.kv_manager.kv().get(&sign_init.substrate_key).await?;
        let bincode = bincode::DefaultOptions::new();
        let value: SecretKeyShare = bincode.deserialize(&party_vec)?;
        let party_info = PartyInfo::get_party_info(
            vec![value.clone()],
            vec!["test".to_string(), "test1".to_string()],
            vec![0],
            TypedUsize::<KeygenShareId>::as_usize(&value.share().index()),
        );
        SignContext::new(sign_init, party_info)
    }

    /// https://github.com/axelarnetwork/tofnd/blob/117a35b808663ceebfdd6e6582a3f0a037151198/src/gg20/sign/execute.rs#L22
    /// handle signing protocol execution.
    #[instrument(skip(channels))]
    pub async fn execute_sign(
        &self,
        ctx: &SignContext,
        channels: Channels,
    ) -> Result<RecoverableSignature, SigningErr> {
        info!("execute_sign: {ctx:?}");
        let new_sign =
            gg20::sign::new_sign(ctx.group(), &ctx.share, &ctx.sign_parties, ctx.msg_to_sign())
                .map_err(|e| SigningErr::ProtocolExecution(format!("{e:?}")))?;
        let sig = tofn_protocol::execute_protocol(
            new_sign,
            channels,
            &ctx.sign_uids(),
            &[1usize, 1usize],
            ctx.party_info.tofnd.index,
        )
        .await?
        .map_err(|e| SigningErr::ProtocolOutput(format!("{e:?}")))?;

        to_recoverable_signature(
            &ctx.party_info.common.verifying_key(),
            ctx.sign_init.msg.as_ref(),
            &sig,
        )
        .ok_or(SigningErr::SignatureError)
    }

    // todo placeholder for any result handling
    #[instrument]
    #[allow(unused_variables)]
    pub fn handle_result(
        &self,
        signature: &RecoverableSignature,
        msg: [u8; 32],
        signatures: &rocket::State<SignatureState>,
    ) {
        signatures.insert(msg, signature);
    }
}
