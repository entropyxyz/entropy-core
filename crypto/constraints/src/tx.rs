//! This module provides (un)signed transaction types and parsing utilities for each architecture,
//! and traits for adding additional architectures to the constraints system.

use crate::Architecture;
use serde::{Deserialize, Serialize};


/// Basic transaction that has a sender and receiver with single accounts.
/// TODO remove this and compose Constraints using trait bounds (eg. GetSender + GetReceiver, etc)
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicTransaction<A: Architecture> {
    pub from: Option<A::Address>,
    pub to: Option<A::Address>,
}
