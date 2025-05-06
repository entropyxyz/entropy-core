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

use crate::chain_spec::{dev::development_genesis_config, get_account_id_from_seed, ChainSpec};

use entropy_runtime::wasm_binary_unwrap;
use entropy_shared::{
    BoundedVecEncodedVerifyingKey, TssPublicKeys, X25519PublicKey as TssX25519PublicKey,
};
use sc_service::ChainType;
use serde::{Deserialize, Serialize};
use sp_core::sr25519;
use sp_runtime::BoundedVec;

const ACCEPTED_MEASUREMENT: [u8; 32] = [0; 32];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TestnetChainSpecInputs {
    /// A map of hostname / socket address to [TssPublicKeys] of the TSS servers
    /// [TssPublicKeys] is the output type returned from the TSS server `/info` http route
    pub tss_details: HashMap<String, TssPublicKeys>,
    /// The accepted build time measurement values from the current entropy-tss VM images
    pub accepted_measurement_values: Vec<[u8; 32]>,
    // TODO pre-endowed accounts
    // Bootnode peer IDs
}

/// The configuration used for the TDX testnet.
///
/// Since Entropy requires at two-of-three threshold setup, and requires an additional relayer node,
/// we spin up four validators: Alice, Bob, Charlie and Dave.
pub fn tdx_testnet_config(inputs: TestnetChainSpecInputs) -> ChainSpec {
    let tss_details = inputs
        .tss_details
        .into_iter()
        .map(|(host, tss_details)| {
            let account_id = sp_runtime::AccountId32::new(tss.tss_account.0);
            (account_id, tss.x25519_public_key, host, tss.provisioning_certification_key)
        })
        .collect();

    let measurement_values = inputs
        .accepted_measurement_values
        .into_iter()
        .map(|value| BoundedVec::try_from(value.to_vec()).unwrap())
        .collect();

    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("TDX-testnet")
        .with_id("tdx")
        .with_chain_type(ChainType::Live)
        .with_genesis_config_patch(testnet_genesis_config(
            testnet_initial_authorities(),
            vec![],
            hex!["b848e84ef81dfeabef80caed10d7d34cc10e98e71fd00c5777b81177a510d871"].into(),
            tss_details,
            Some(measurement_values),
        ))
        .with_protocol_id(crate::chain_spec::DEFAULT_PROTOCOL_ID)
        .with_properties(crate::chain_spec::entropy_properties())
        .with_telemetry_endpoints(
            TelemetryEndpoints::new(vec![(
                crate::chain_spec::STAGING_TELEMETRY_URL.to_string(),
                0,
            )])
            .expect("Staging telemetry url is valid; qed"),
        )
        .build()
}
