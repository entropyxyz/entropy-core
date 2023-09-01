#![allow(dead_code)]

use std::collections::HashSet;

use sp_core::crypto::AccountId32;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::Broadcaster;
use crate::{
    signing_client::{ProtocolMessage, SubscribeErr},
    user::api::ValidatorInfo,
};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

/// Tracks which validators we are connected to and sets up channels for exchaning protocol messages
#[derive(Debug)]
pub struct Listener {
    /// Endpoint to create subscriptions
    tx: broadcast::Sender<ProtocolMessage>,
    /// Messages
    tx_to_others: mpsc::Sender<ProtocolMessage>,
    /// Endpoint to notify protocol execution ready-for-signing
    tx_ready: oneshot::Sender<ListenerResult>,
    /// Remaining validators we want to connect to
    validators: HashSet<AccountId32>,
    /// The Validator Info associated with this listener
    pub validators_info: Vec<ValidatorInfo>,
}

/// Channels between a remote party and the signing or DKG protocol
pub struct WsChannels {
    pub broadcast: broadcast::Receiver<ProtocolMessage>,
    pub tx: mpsc::Sender<ProtocolMessage>,
    /// A flag to show that this is the last connection to be set up, and we can proceed with the
    /// protocol
    pub is_final: bool,
}

impl Listener {
    pub(crate) fn new(
        validators_info: Vec<ValidatorInfo>,
        my_id: &AccountId32,
    ) -> (oneshot::Receiver<ListenerResult>, mpsc::Receiver<ProtocolMessage>, Self) {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        let (tx_to_others, rx_to_others) = mpsc::channel(1000);

        // Create our set of validators we want to connect to - excluding ourself
        let validators = validators_info
            .iter()
            .map(|validator_info| validator_info.tss_account.clone())
            .filter(|id| id != my_id)
            .collect();

        {
            (
                rx_ready,
                rx_to_others,
                Self { tx, tx_to_others, tx_ready, validators, validators_info },
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
