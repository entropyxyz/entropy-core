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

use crate::{
    chain_api::{get_api, get_rpc, EntropyConfig},
    spawn_testing_validators,
    substrate_context::{test_context_stationary, test_node_process_testing_state},
    ChainSpecType,
};
use entropy_protocol::PartyId;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};

/// A helper for setting up tests which starts both a set of TS servers and a chain node and returns
/// the chain API as well as IP addresses and PartyId of the started validators
pub async fn spawn_tss_nodes_and_start_chain(
    add_parent_key: bool,
    chain_spec_type: ChainSpecType,
) -> (OnlineClient<EntropyConfig>, LegacyRpcMethods<EntropyConfig>, Vec<String>, Vec<PartyId>) {
    let (validator_ips, validator_ids) =
        spawn_testing_validators(add_parent_key, chain_spec_type.clone()).await;

    let (api, rpc) = match chain_spec_type {
        ChainSpecType::Development => {
            let substrate_context = test_context_stationary().await;
            (
                get_api(&substrate_context.node_proc.ws_url).await.unwrap(),
                get_rpc(&substrate_context.node_proc.ws_url).await.unwrap(),
            )
        },
        ChainSpecType::Integration => {
            // Here we need to use `--chain=integration-tests` and force authoring otherwise we won't be
            // able to get our chain in the right state to be jump started.
            let force_authoring = true;
            let substrate_context = test_node_process_testing_state(force_authoring).await;
            (
                get_api(&substrate_context.ws_url).await.unwrap(),
                get_rpc(&substrate_context.ws_url).await.unwrap(),
            )
        },
    };
    (api, rpc, validator_ips, validator_ids)
}
