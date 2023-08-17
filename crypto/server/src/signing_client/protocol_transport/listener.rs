#![allow(dead_code)]

use std::collections::HashMap;

use entropy_shared::X25519PublicKey;
use sp_core::crypto::AccountId32;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::Broadcaster;
use crate::{
    signing_client::{SigningMessage, SubscribeErr},
    user::api::UserTransactionRequest,
};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

/// Tracks which validators we are connected to for a particular protocol execution
/// and sets up channels for exchaning protocol messages
#[derive(Debug)]
pub struct Listener {
    /// Endpoint to create subscriptions
    tx: broadcast::Sender<SigningMessage>,
    /// Messages
    tx_to_others: mpsc::Sender<SigningMessage>,
    /// Endpoint to notify protocol execution ready-for-signing
    tx_ready: oneshot::Sender<ListenerResult>,
    /// Remaining validators we want to connect to
    pub validators: HashMap<AccountId32, X25519PublicKey>,
    /// The request message associated with this listener
    pub user_transaction_request: UserTransactionRequest,
}

/// Channels between a remote party and the signing protocol
pub struct WsChannels {
    pub broadcast: broadcast::Receiver<SigningMessage>,
    pub tx: mpsc::Sender<SigningMessage>,
    /// A flag to show that this is the last connection to be set up, and we can proceed with the
    /// protocol
    pub is_final: bool,
}

impl Listener {
    pub(crate) fn new(
        user_transaction_request: UserTransactionRequest,
        my_id: &AccountId32,
        user_participates: Option<(AccountId32, X25519PublicKey)>,
    ) -> (oneshot::Receiver<ListenerResult>, mpsc::Receiver<SigningMessage>, Self) {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        let (tx_to_others, rx_to_others) = mpsc::channel(1000);

        // Create our set of validators we want too connect to - excluding ourself
        let mut validators = HashMap::new();

        for validator in user_transaction_request.validators_info.clone() {
            if &validator.tss_account != my_id {
                validators.insert(validator.tss_account, validator.x25519_public_key);
            }
        }

        // If visibility is private, also expect the user to connect
        if let Some((user_id, user_x25519_pk)) = user_participates {
            validators.insert(user_id, user_x25519_pk);
        }

        {
            (
                rx_ready,
                rx_to_others,
                Self { tx, tx_to_others, tx_ready, validators, user_transaction_request },
            )
        }
    }

    /// Check that the given account is in the signing group, and if so return channels to the
    /// protocol
    pub(crate) fn subscribe(
        &mut self,
        account_id: &AccountId32,
    ) -> Result<WsChannels, SubscribeErr> {
        if self.validators.remove(account_id).is_some() {
            let broadcast = self.tx.subscribe();
            let tx = self.tx_to_others.clone();
            Ok(WsChannels { broadcast, tx, is_final: self.validators.is_empty() })
        } else {
            Err(SubscribeErr::InvalidPartyId(
                "Validator is not expected for this message".to_string(),
            ))
        }
    }

    /// When all connections are set up, convert to a broadcaster and proceed with the protocol
    pub(crate) fn into_broadcaster(self) -> (oneshot::Sender<ListenerResult>, Broadcaster) {
        (self.tx_ready, Broadcaster(self.tx))
    }
}
