//! Custom error types for [kv_manager].

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
