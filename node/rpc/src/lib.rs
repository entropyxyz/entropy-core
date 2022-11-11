// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate system API.

use frame_support::log;
use jsonrpsee::{
    core::{async_trait, Error as JsonRpseeError, RpcResult},
    proc_macros::rpc,
    types::error::{CallError, ErrorCode, ErrorObject},
};
use pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi;
use rustc_hex::ToHex;
use sc_rpc_api::DenyUnsafe;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{Bytes, Decode, H160, U256};
use sp_rpc::number::NumberOrHex;
use sp_runtime::{
    codec::Codec,
    generic::BlockId,
    traits::{self, Block as BlockT, MaybeDisplay, MaybeFromStr},
    SaturatedConversion,
};
use std::{marker::PhantomData, sync::Arc};

use pallet_staking_extension::ServerInfo;

/// Substrate system RPC API
#[rpc(client, server)]
pub trait ExampleApi {
    /// Returns the stash, threshold server, and X25519 keys associated with a validator's controller account..
    #[method(name = "stakingExtension_exampleRpc")]
    fn example_rpc(&self, number: u64) -> RpcResult<Option<u64>>;
}
// #[rpc(client, server)]
// pub trait StakingExtensionApi<AccountId> {
//     /// Returns the stash, threshold server, and X25519 keys associated with a validator's controller account..
//     #[method(name = "stakingExtension_getTsServerInfo")]
//     async fn get_ts_server_info(
//         &self,
//         validator_stash: AccountId,
//     ) -> RpcResult<Option<ServerInfo<AccountId>>>;
// }

// pub struct StakingExtension<B, C> {
//     client: Arc<C>,
//     _deny_unsafe: DenyUnsafe,
// }

pub struct Example;
impl Example {
    pub fn new() -> Self {
        Self
    }
}

// impl<B, C, Balance> StakingExtension<B, C> {
//     pub fn new(client: Arc<C>, _deny_unsafe: DenyUnsafe) -> Self {
//         Self { client, _deny_unsafe }
//     }
// }

impl ExampleApiServer for Example {
    fn example_rpc(&self, number: u64) -> RpcResult<Option<u64>> {
        Ok(Some(number * 2))
    }
}

// impl<C, Block> StakingExtensionApiServer<<Block as BlockT>::Hash>>
//     for TransactionPayment<C, Block>
// where
//     Block: BlockT + 'static,
//     C: Send + Sync + 'static,
// {
//     fn get_ts_server_info(
//         &self,
//         validator_stash: AccountId,
//     ) -> RpcResult<Option<ServerInfo<AccountId>>> {
//         Ok(().into())
//     }
// }
