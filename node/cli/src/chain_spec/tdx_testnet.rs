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
use entropy_shared::{BoundedVecEncodedVerifyingKey, X25519PublicKey as TssX25519PublicKey};
use sc_service::ChainType;
use sp_core::sr25519;
use sp_runtime::BoundedVec;

/// The build time measurement value from the current entropy-tss VM images
const ACCEPTED_MRTD: [u8; 48] = [
    145, 235, 43, 68, 209, 65, 212, 236, 224, 159, 12, 117, 194, 197, 61, 36, 122, 60, 104, 237,
    215, 250, 254, 138, 53, 32, 201, 66, 166, 4, 164, 7, 222, 3, 174, 109, 197, 248, 127, 39, 66,
    139, 37, 56, 135, 49, 24, 183,
];

lazy_static::lazy_static! {
    pub static ref PCK: BoundedVecEncodedVerifyingKey = vec![
    2, 166, 103, 136, 58, 157, 155, 124, 186, 75, 81, 133, 87, 255, 233, 182, 192, 125, 235, 230,
    121, 173, 147, 108, 47, 190, 240, 181, 75, 181, 31, 148, 128,
    ].try_into().unwrap();
}

fn tdx_devnet_four_node_initial_tss_servers(
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String, BoundedVecEncodedVerifyingKey)> {
    let tss_ip = std::env::var("ENTROPY_TESTNET_TSS_IP")
        .expect("ENTROPY_TESTNET_TSS_IP environment variable to be set");

    let alice = (
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_x25519_public_key::ALICE,
        format!("{tss_ip}:3001"),
        PCK.clone(),
    );

    let bob = (
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_x25519_public_key::BOB,
        format!("{tss_ip}:3002"),
        PCK.clone(),
    );

    let charlie = (
        crate::chain_spec::tss_account_id::CHARLIE.clone(),
        crate::chain_spec::tss_x25519_public_key::CHARLIE,
        format!("{tss_ip}:3003"),
        PCK.clone(),
    );

    let dave = (
        crate::chain_spec::tss_account_id::DAVE.clone(),
        crate::chain_spec::tss_x25519_public_key::DAVE,
        format!("{tss_ip}:3004"),
        PCK.clone(),
    );

    vec![alice, bob, charlie, dave]
}

/// The configuration used for development.
///
/// Since Entropy requires at two-of-three threshold setup, and requires an additional relayer node,
/// we spin up four validators: Alice, Bob, Charlie and Dave.
pub fn development_config() -> ChainSpec {
    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("Development")
        .with_id("dev")
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
            tdx_devnet_four_node_initial_tss_servers(),
            Some(vec![BoundedVec::try_from(ACCEPTED_MRTD.to_vec()).unwrap()]),
        ))
        .build()
}
