#![allow(dead_code)]

use std::collections::HashMap;

use entropy_protocol::{
    protocol_transport::{Broadcaster, WsChannels},
    ProtocolMessage, ValidatorInfo,
};
use entropy_shared::X25519PublicKey;
use sp_core::crypto::AccountId32;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::signing_client::SubscribeErr;

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

/// Tracks which validators we are connected to for a particular protocol execution
/// and sets up channels for exchaning protocol messages
#[derive(Debug)]
pub struct Listener {
    /// Endpoint to create subscriptions
    tx: broadcast::Sender<ProtocolMessage>,
    /// Messages
    tx_to_others: mpsc::Sender<ProtocolMessage>,
    /// Endpoint to notify protocol execution ready-for-signing
    tx_ready: oneshot::Sender<ListenerResult>,
    /// Remaining validators we want to connect to
    pub validators: HashMap<AccountId32, X25519PublicKey>,
}

impl Listener {
    pub(crate) fn new(
        validators_info: Vec<ValidatorInfo>,
        my_id: &AccountId32,
        user_participates: Option<(AccountId32, X25519PublicKey)>,
    ) -> (oneshot::Receiver<ListenerResult>, mpsc::Receiver<ProtocolMessage>, Self) {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        let (tx_to_others, rx_to_others) = mpsc::channel(1000);

        // Create our set of validators we want too connect to - excluding ourself
        let mut validators = HashMap::new();

        for validator in validators_info {
            if &validator.tss_account != my_id {
                validators.insert(validator.tss_account, validator.x25519_public_key);
            }
        }

        // If visibility is private, also expect the user to connect
        if let Some((user_id, user_x25519_pk)) = user_participates {
            validators.insert(user_id, user_x25519_pk);
        }

        {
            (rx_ready, rx_to_others, Self { tx, tx_to_others, tx_ready, validators })
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
