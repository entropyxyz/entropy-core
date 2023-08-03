#![allow(dead_code)]

use std::collections::HashSet;

use sp_core::crypto::AccountId32;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::Broadcaster;
use crate::{
    signing_client::{SigningMessage, SubscribeErr},
    user::api::UserTransactionRequest,
};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

/// Tracks which validators we are connected to and sets up channels for exchaning protocol messages
#[derive(Debug)]
pub struct Listener {
    /// Endpoint to create subscriptions
    tx: broadcast::Sender<SigningMessage>,
    /// Messages
    tx_to_others: mpsc::Sender<SigningMessage>,
    /// Endpoint to notify protocol execution ready-for-signing
    tx_ready: oneshot::Sender<ListenerResult>,
    /// Remaining validators we want to connect to
    validators: HashSet<AccountId32>,
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
    // TODO only pass validaitor info to reuse
    pub(crate) fn new(
        user_transaction_request: UserTransactionRequest,
        my_id: &AccountId32,
    ) -> (oneshot::Receiver<ListenerResult>, mpsc::Receiver<SigningMessage>, Self) {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        let (tx_to_others, rx_to_others) = mpsc::channel(1000);

        // Create our set of validators we want to connect to - excluding ourself
        let validators = user_transaction_request
            .validators_info
            .iter()
            .map(|validator_info| validator_info.tss_account.clone())
            .filter(|id| id != my_id)
            .collect();

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
        if self.validators.remove(account_id) {
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
