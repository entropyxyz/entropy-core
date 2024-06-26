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

use synedrion::{
    sessions, InteractiveSigningResult, KeyGenResult, KeyRefreshResult, ProtocolResult,
};
use thiserror::Error;

use crate::{
    protocol_message::ProtocolMessage, protocol_transport::errors::EncryptedConnectionErr,
    KeyParams, PartyId,
};

#[derive(Debug, Error)]
pub enum GenericProtocolError<Res: ProtocolResult> {
    #[error("Synedrion session error {0}")]
    Joined(Box<sessions::Error<Res, PartyId>>),
    #[error("Incoming message stream error: {0}")]
    IncomingStream(String),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<ProtocolMessage>>),
}

impl<Res: ProtocolResult> From<sessions::LocalError> for GenericProtocolError<Res> {
    fn from(err: sessions::LocalError) -> Self {
        Self::Joined(Box::new(sessions::Error::Local(err)))
    }
}

impl<Res: ProtocolResult> From<sessions::RemoteError<PartyId>> for GenericProtocolError<Res> {
    fn from(err: sessions::RemoteError<PartyId>) -> Self {
        Self::Joined(Box::new(sessions::Error::Remote(err)))
    }
}

impl<Res: ProtocolResult> From<sessions::Error<Res, PartyId>> for GenericProtocolError<Res> {
    fn from(err: sessions::Error<Res, PartyId>) -> Self {
        Self::Joined(Box::new(err))
    }
}

impl From<GenericProtocolError<InteractiveSigningResult<KeyParams>>> for ProtocolExecutionErr {
    fn from(err: GenericProtocolError<InteractiveSigningResult<KeyParams>>) -> Self {
        match err {
            GenericProtocolError::Joined(err) => ProtocolExecutionErr::SigningProtocolError(err),
            GenericProtocolError::IncomingStream(err) => ProtocolExecutionErr::IncomingStream(err),
            GenericProtocolError::Broadcast(err) => ProtocolExecutionErr::Broadcast(err),
        }
    }
}

impl From<GenericProtocolError<KeyGenResult<KeyParams>>> for ProtocolExecutionErr {
    fn from(err: GenericProtocolError<KeyGenResult<KeyParams>>) -> Self {
        match err {
            GenericProtocolError::Joined(err) => ProtocolExecutionErr::KeyGenProtocolError(err),
            GenericProtocolError::IncomingStream(err) => ProtocolExecutionErr::IncomingStream(err),
            GenericProtocolError::Broadcast(err) => ProtocolExecutionErr::Broadcast(err),
        }
    }
}

impl From<GenericProtocolError<KeyRefreshResult<KeyParams>>> for ProtocolExecutionErr {
    fn from(err: GenericProtocolError<KeyRefreshResult<KeyParams>>) -> Self {
        match err {
            GenericProtocolError::Joined(err) => ProtocolExecutionErr::KeyRefreshProtocolError(err),
            GenericProtocolError::IncomingStream(err) => ProtocolExecutionErr::IncomingStream(err),
            GenericProtocolError::Broadcast(err) => ProtocolExecutionErr::Broadcast(err),
        }
    }
}

/// An error during or while setting up a protocol session
#[derive(Debug, Error)]
pub enum ProtocolExecutionErr {
    #[error("Incoming message stream error: {0}")]
    IncomingStream(String),
    #[error("Synedrion session creation error: {0}")]
    SessionCreation(sessions::LocalError),
    #[error("Synedrion signing session error {0}")]
    SigningProtocolError(Box<sessions::Error<InteractiveSigningResult<KeyParams>, PartyId>>),
    #[error("Synedrion keygen session error {0}")]
    KeyGenProtocolError(Box<sessions::Error<KeyGenResult<KeyParams>, PartyId>>),
    #[error("Synedrion key refresh session error {0}")]
    KeyRefreshProtocolError(Box<sessions::Error<KeyRefreshResult<KeyParams>, PartyId>>),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<ProtocolMessage>>),
    #[error("Bad keyshare error {0}")]
    BadKeyShare(String),
    #[error("Cannot serialize session ID {0}")]
    Bincode(#[from] bincode::Error),
}

/// An error when running a protocol session on the client side
#[derive(Debug, Error)]
pub enum UserRunningProtocolErr {
    #[error("Encrypted Connection Error: {0}")]
    EncryptedConnection(#[from] EncryptedConnectionErr),
    #[error("Protocol Execution Error {0}")]
    SigningProtocolExecution(#[from] GenericProtocolError<InteractiveSigningResult<KeyParams>>),
    #[error("Protocol Execution Error {0}")]
    ProtocolExecution(#[from] ProtocolExecutionErr),
    #[error("Serialization Error: {0:?}")]
    Serialization(#[from] bincode::Error),
    #[error("Bad Subscribe Message: {0}")]
    BadSubscribeMessage(String),
    #[error("Connection Error: {0}")]
    Connection(String),
}

#[derive(Debug, Error)]
pub enum ListenerErr {
    #[error("invalid party ID: {0}")]
    InvalidPartyId(String),
}
