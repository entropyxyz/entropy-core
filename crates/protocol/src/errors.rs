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

use manul::protocol::LocalError;
use thiserror::Error;

use crate::protocol_message::ProtocolMessage;

/// An error during or while setting up a protocol session
#[derive(Debug, Error)]
pub enum ProtocolExecutionErr {
    #[error("Incoming message stream error: {0}")]
    IncomingStream(String),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<ProtocolMessage>>),
    #[error("Mpsc send error: {0}")]
    Mpsc(String),
    #[error("Bad keyshare error {0}")]
    BadKeyShare(String),
    #[error("Cannot serialize session ID {0}")]
    Bincode(#[from] bincode::Error),
    #[error("No output from reshare protocol")]
    NoOutputFromReshareProtocol,
    #[error("BigInt conversion: {0}")]
    BigIntConversion(#[from] num::bigint::TryFromBigIntError<num::bigint::BigUint>),
    #[error("Index out of bounds when selecting DKG committee")]
    IndexOutOfBounds,
    #[error("Received bad validating key {0}")]
    BadVerifyingKey(String),
    #[error("Expected verifying key but got a protocol message")]
    UnexpectedMessage,
    #[error("Message processing task panic or cancellation: {0}")]
    JoinHandle(#[from] tokio::task::JoinError),
    #[error("Could not get validating key from keyshare")]
    NoValidatingKey,
    #[error("Manul local error {0}")]
    Local(String),
    #[error("The protocol session was terminated by the user")]
    Terminated,
    #[error("The protocol execution stalled because not enough messages were received to finalize the round")]
    NotEnoughMessages,
    #[error("Could not sent stop signal to incoming message handler - likely the handler has already terminated")]
    StopSignal(#[from] tokio::sync::mpsc::error::SendError<()>),
}

impl From<LocalError> for ProtocolExecutionErr {
    fn from(err: LocalError) -> Self {
        Self::Mpsc(format!("{err:?}"))
    }
}

impl From<tokio::sync::mpsc::error::SendError<ProtocolMessage>> for ProtocolExecutionErr {
    fn from(err: tokio::sync::mpsc::error::SendError<ProtocolMessage>) -> Self {
        Self::Local(format!("{err:?}"))
    }
}

#[derive(Debug, Error)]
pub enum ListenerErr {
    #[error("invalid party ID: {0}")]
    InvalidPartyId(String),
}

/// An error when handling a verifying key
#[derive(Debug, Error)]
pub enum VerifyingKeyError {
    #[error("Could not decode to encoded point")]
    DecodeEncodedPoint,
    #[error("Could not convert encoded point to verifying key")]
    EncodedPointToVerifyingKey,
}
