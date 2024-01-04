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

//! Custom error types for [crate::kv_manager].

use crate::encrypted_sled;

#[allow(clippy::enum_variant_names)] // allow Err postfix
#[derive(thiserror::Error, Debug)]
pub enum KvError {
    #[error("Kv initialization Error: {0}")]
    InitErr(#[from] encrypted_sled::Error),
    #[error("Recv Error: {0}")] // errors receiving from "actor pattern"'s channels
    RecvErr(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Send Error: {0}")] // errors sending to "actor pattern"'s channels
    SendErr(String),
    #[error("Reserve Error: {0}")]
    ReserveErr(InnerKvError),
    #[error("Put Error: {0}")]
    PutErr(InnerKvError),
    #[error("Get Error: {0}")]
    GetErr(InnerKvError),
    #[error("Delete Error: {0}")]
    DeleteErr(InnerKvError),
    #[error("Exits Error: {0}")]
    ExistsErr(InnerKvError),
}
pub type KvResult<Success> = Result<Success, KvError>;

#[allow(clippy::enum_variant_names)] // allow Err postfix
#[derive(thiserror::Error, Debug)]
pub enum InnerKvError {
    #[error("Sled Error: {0}")] // Delegate Sled's errors
    SledErr(#[from] encrypted_sled::Error),
    #[error("Logical Error: {0}")] // Logical errors (eg double deletion)
    LogicalErr(String),
    #[error("Serialization Error: failed to serialize value")]
    SerializationErr,
    #[error("Deserialization Error: failed to deserialize kvstore bytes")]
    DeserializationErr,
}

pub(super) type InnerKvResult<Success> = Result<Success, InnerKvError>;
