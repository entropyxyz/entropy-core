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

use crate::chain_spec::{
    dev::development_genesis_config, get_account_id_from_seed, ChainSpec, MeasurementValues,
};

use entropy_runtime::wasm_binary_unwrap;
use entropy_shared::{
    tss_node_info::{BuildDetails, TssPublicKeys, VersionDetails},
    BoundedVecEncodedVerifyingKey, X25519PublicKey as TssX25519PublicKey,
};
use sc_service::ChainType;
use sp_core::sr25519;
use sp_runtime::BoundedVec;

lazy_static::lazy_static! {
    /// This is the PCK from the certificates of the current TDX machine we are using for testing
    pub static ref PCK: BoundedVecEncodedVerifyingKey = vec![
    2, 166, 103, 136, 58, 157, 155, 124, 186, 75, 81, 133, 87, 255, 233, 182, 192, 125, 235, 230,
    121, 173, 147, 108, 47, 190, 240, 181, 75, 181, 31, 148, 128,
    ].try_into().unwrap();
}

fn tdx_devnet_four_node_initial_tss_servers(
    tss_endpoints: [String; 4],
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String, BoundedVecEncodedVerifyingKey)> {
    let client = reqwest::blocking::Client::new();

    tss_endpoints
        .iter()
        .map(|tss_endpoint| {
            // Get the public keys of the 4 TSS nodes running at genesis
            let details: TssPublicKeys =
                client.get(format!("{tss_endpoint}/info")).send().unwrap().json().unwrap();

            (
                details.tss_account,
                details.x25519_public_key,
                tss_endpoint.clone(),
                details.provisioning_certification_key,
            )
        })
        .collect()
}

/// The configuration used for the TDX testnet.
///
/// Since Entropy requires at two-of-three threshold setup, and requires an additional relayer node,
/// we spin up four validators: Alice, Bob, Charlie and Dave.
pub fn tdx_testnet_config(tss_endpoints: [String; 4]) -> ChainSpec {
    let measurement_values = get_measurement_values(&tss_endpoints);

    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("TDX-testnet")
        .with_id("tdx")
        .with_chain_type(ChainType::Development)
        .with_properties(crate::chain_spec::entropy_properties())
        .with_genesis_config_patch(development_genesis_config(
            vec![
                crate::chain_spec::authority_keys_from_seed("Alice"),
                crate::chain_spec::authority_keys_from_seed("Bob"),
                crate::chain_spec::authority_keys_from_seed("Charlie"),
                crate::chain_spec::authority_keys_from_seed("Dave"),
            ],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            tdx_devnet_four_node_initial_tss_servers(tss_endpoints),
            Some(measurement_values),
        ))
        .build()
}

/// Get the measurement value for the currently deployed TSS nodes
fn get_measurement_values(tss_endpoints: &[String; 4]) -> MeasurementValues {
    let client = reqwest::blocking::Client::new();
    let version_details: VersionDetails =
        client.get(format!("{}/version", tss_endpoints[0])).send().unwrap().json().unwrap();
    if let BuildDetails::ProductionWithMeasurementValue(measurement_value) = version_details.build {
        return vec![BoundedVec::try_from(hex::decode(measurement_value).unwrap()).unwrap()];
    }
    panic!("Not a production entropy-tss build");
}
