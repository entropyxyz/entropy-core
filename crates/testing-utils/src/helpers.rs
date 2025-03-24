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
    substrate_context::test_node_process_testing_state,
    ChainSpecType, TestNodeProcess,
};
use entropy_protocol::PartyId;
use rand::{rngs::StdRng, SeedableRng};
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};
pub use tdx_quote::encode_verifying_key;

pub struct TssTestingResult {
    pub substrate_context: Vec<TestNodeProcess<EntropyConfig>>,
    pub api: OnlineClient<EntropyConfig>,
    pub rpc: LegacyRpcMethods<EntropyConfig>,
    pub validator_ips: Vec<String>,
    pub validator_ids: Vec<PartyId>,
}

/// A helper for setting up tests which starts both a set of TS servers and a chain node and returns
/// the chain API as well as IP addresses and PartyId of the started validators
///
/// Note that since this function does not reside in entropy-tss, cfg(test) will be false when the
/// TSS nodes are set up, meaning the unsafe API will not be enabled
pub async fn spawn_tss_nodes_and_start_chain(chain_spec_type: ChainSpecType) -> TssTestingResult {
    let (validator_ips, validator_ids) = spawn_testing_validators(chain_spec_type).await;

    // Here we need to force authoring otherwise we won't be able to get our chain in the right
    // state to be jump started.
    let force_authoring = false;
    let substrate_context = test_node_process_testing_state(chain_spec_type, force_authoring).await;
    let api = get_api(&substrate_context[0].ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context[0].ws_url).await.unwrap();

    TssTestingResult { substrate_context, api, rpc, validator_ips, validator_ids }
}

/// Get the mock PCK that will be used for a given TSS account ID
pub fn derive_mock_pck_verifying_key(tss_account_id: &AccountId32) -> tdx_quote::VerifyingKey {
    let mut pck_seeder = StdRng::from_seed(tss_account_id.0);
    let pck = tdx_quote::SigningKey::random(&mut pck_seeder);
    tdx_quote::VerifyingKey::from(pck)
}

/// For each test TSS account, display the encoded mock PCK
pub fn print_test_pck_verifying_keys() {
    for tss_account in crate::constants::TSS_ACCOUNTS.iter() {
        let pck = derive_mock_pck_verifying_key(tss_account);
        println!("{:?}", encode_verifying_key(&pck));
    }
}
