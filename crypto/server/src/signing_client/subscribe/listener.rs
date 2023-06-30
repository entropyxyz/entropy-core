#![allow(dead_code)]

use std::collections::HashSet;

use sp_core::crypto::AccountId32;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::Broadcaster;
use crate::signing_client::{SigningMessage, SubscribeErr};

pub type ListenerResult = Result<Broadcaster, SubscribeErr>;

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
}

pub struct WsChannels {
    pub broadcast: broadcast::Receiver<SigningMessage>,
    pub tx: mpsc::Sender<SigningMessage>,
    pub is_final: bool,
}

impl Listener {
    pub(crate) fn new(
        validators_vec: Vec<AccountId32>,
        my_id: &AccountId32,
    ) -> (oneshot::Receiver<ListenerResult>, mpsc::Receiver<SigningMessage>, Self) {
        let (tx_ready, rx_ready) = oneshot::channel();
        let (tx, _rx) = broadcast::channel(1000);
        let (tx_to_others, rx_to_others) = mpsc::channel(1000);
        {
            (
                rx_ready,
                rx_to_others,
                Self {
                    tx,
                    tx_to_others,
                    tx_ready,
                    validators: validators_vec.into_iter().filter(|id| id != my_id).collect(),
                },
            )
        }
    }

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

    pub(crate) fn into_broadcaster(self) -> (oneshot::Sender<ListenerResult>, Broadcaster) {
        (self.tx_ready, Broadcaster(self.tx))
    }
}
