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

// Copyright (C) Parity Technologies (UK) Ltd.
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

//! Substrate chain configurations.

pub mod dev;
pub mod integration_tests;
pub mod tdx_testnet;
pub mod testnet;

pub use entropy_runtime::{AccountId, RuntimeGenesisConfig, Signature};

use entropy_runtime::{Block, SessionKeys};
use grandpa_primitives::AuthorityId as GrandpaId;
use hex_literal::hex;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_chain_spec::{ChainSpecExtension, Properties};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::{
    traits::{ConstU32, IdentifyAccount, Verify},
    BoundedVec,
};

type AccountPublic = <Signature as Verify>::Signer;

const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";
const DEFAULT_PROTOCOL_ID: &str = "Entropy"; // TODO finalize

/// The `AccountId` represending a Threshold Signature Scheme servers (TSS).
///
/// This gets stored on-chain to and is used to identify a particular TSS.
pub mod tss_account_id {
    lazy_static::lazy_static! {

    /// The `DEFAULT_ALICE_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
    pub static ref ALICE: sp_runtime::AccountId32 =
            super::hex!["306bdb49cbbe7104e3621abab3c9d31698b159f48dafe567abb7ea5d872ed329"].into();

    /// The `DEFAULT_BOB_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "where sight patient orphan general short empower hope party hurt month voice"
    pub static ref BOB: sp_runtime::AccountId32  =
            super::hex!["2cbc68e8bf0fbc1c28c282d1263fc9d29267dc12a1044fb730e8b65abc37524c"].into();

    /// The `DEFAULT_CHARLIE_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "lake carry still awful point mention bike category tornado plate brass lock"
    pub static ref CHARLIE: sp_runtime::AccountId32  =
            super::hex!["946140d3d5ddb980c74ffa1bb64353b5523d2d77cdf3dc617fd63de9d3b66338"].into();

    /// The `DEFAULT_DAVE_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "beef dutch panic monkey black glad audit twice humor gossip wealth drive"
    pub static ref DAVE: sp_runtime::AccountId32  =
            super::hex!["0a9054ef6b6b8ad0dd2c89895b2515583f2fbf1edced68e7328ae456d86b9402"].into();

    /// The `DEFAULT_EVE_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "impact federal dish number fun crisp various wedding radio immense whisper glue"
    pub static ref EVE: sp_runtime::AccountId32  =
            super::hex!["ac0d9030598f1722ff7c6a2a3043fa65903448dcc7a23011ec06c1c31cdad120"].into();

    }
}

/// The X25519 public key used by the Threshold Signature Scheme servers (TSS) to encrypt messages
/// between TSS servers.
pub mod tss_x25519_public_key {
    /// The `DEFAULT_ALICE_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
    pub const ALICE: [u8; 32] = [
        8, 22, 19, 230, 107, 217, 249, 190, 14, 142, 155, 252, 156, 229, 120, 11, 180, 35, 83, 245,
        222, 11, 153, 201, 162, 29, 153, 13, 123, 126, 128, 32,
    ];
    /// The `DEFAULT_BOB_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "where sight patient orphan general short empower hope party hurt month voice"
    pub const BOB: [u8; 32] = [
        196, 53, 98, 10, 160, 169, 139, 48, 194, 230, 69, 64, 165, 48, 133, 110, 38, 64, 184, 113,
        255, 201, 253, 212, 217, 21, 252, 57, 253, 78, 0, 56,
    ];

    /// The `DEFAULT_CHARLIE_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "lake carry still awful point mention bike category tornado plate brass lock"
    pub const CHARLIE: [u8; 32] = [
        131, 8, 162, 77, 237, 245, 226, 179, 250, 79, 121, 250, 174, 181, 227, 122, 205, 181, 188,
        4, 37, 87, 150, 250, 210, 151, 203, 137, 188, 134, 124, 108,
    ];

    // The `DEFAULT_DAVE_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "beef dutch panic monkey black glad audit twice humor gossip wealth drive"
    pub const DAVE: [u8; 32] = [
        165, 202, 97, 104, 222, 190, 168, 183, 231, 63, 209, 233, 19, 185, 187, 200, 10, 29, 102,
        240, 39, 50, 140, 15, 124, 112, 94, 121, 44, 182, 40, 71,
    ];

    // The `DEFAULT_EVE_MNEMONIC` is used to derive the public key for the tss version of eve
    /// Mnemonic: "impact federal dish number fun crisp various wedding radio immense whisper glue"
    #[allow(dead_code)]
    pub const EVE_TSS: [u8; 32] = [
        66, 106, 241, 196, 65, 224, 212, 85, 99, 184, 198, 249, 172, 237, 47, 2, 151, 182, 0, 74,
        210, 39, 102, 193, 107, 13, 12, 153, 27, 83, 146, 63,
    ];
}

/// Mock provisioning certification keys for attestation of the test TS servers.
/// These are generated deterministically from their TSS account IDs using the helper function
/// entropy_testing_utils::helpers::print_test_pck_verifying_keys
pub mod provisioning_certification_key {
    use entropy_shared::BoundedVecEncodedVerifyingKey;

    lazy_static::lazy_static! {
        pub static ref ALICE: BoundedVecEncodedVerifyingKey = vec![
            2, 137, 55, 65, 52, 103, 166, 204, 247, 160, 46, 220, 5, 113, 151, 217, 157, 196, 11,
            240, 175, 82, 148, 230, 31, 245, 207, 194, 3, 74, 121, 184, 20
        ].try_into().unwrap();
        pub static ref BOB: BoundedVecEncodedVerifyingKey = vec![
            3, 83, 163, 234, 166, 114, 67, 146, 122, 122, 99, 236, 205, 116, 209, 45, 230, 107, 62,
            55, 147, 38, 185, 203, 157, 147, 156, 173, 233, 58, 134, 162, 156].try_into().unwrap();
        pub static ref CHARLIE: BoundedVecEncodedVerifyingKey = vec![
            2, 167, 50, 42, 76, 239, 190, 42, 72, 64, 110, 90, 172, 253, 252, 148, 115, 107, 34, 110,
            2, 112, 184, 147, 87, 71, 63, 217, 238, 89, 253, 97, 176
        ].try_into().unwrap();
        pub static ref DAVE: BoundedVecEncodedVerifyingKey = vec![
            3, 68, 52, 130, 44, 84, 174, 32, 55, 213, 192, 7, 121, 188, 19, 231, 134, 47, 223, 166,
            199, 118, 161, 203, 142, 75, 184, 108, 165, 70, 251, 249, 142
        ].try_into().unwrap();
        pub static ref EVE: BoundedVecEncodedVerifyingKey = vec![
            2, 60, 115, 185, 180, 118, 177, 23, 3, 49, 65, 92, 230, 60, 245, 1, 140, 149, 117, 238,
            83, 69, 110, 30, 140, 31, 60, 69, 38, 34, 202, 242, 125
        ].try_into().unwrap();
    }
}

/// The acceptable TDX measurement value for non-production chainspecs.
/// This is the measurement given in mock quotes. Mock quotes have all zeros for each of the 5
/// 48 bit measurement registers. The overall measurement is the Blake2b hash of these values.
/// So this is the Blake2b hash of 5 * 48 zero bytes.
pub const MEASUREMENT_VALUE_MOCK_QUOTE: [u8; 32] = [
    91, 172, 96, 209, 130, 160, 167, 174, 152, 184, 193, 27, 88, 59, 117, 235, 74, 39, 194, 69,
    147, 72, 129, 25, 224, 24, 189, 103, 224, 20, 107, 116,
];

fn entropy_properties() -> Properties {
    json!({"tokenDecimals": 10, "tokenSymbol": "BITS" }).as_object().unwrap().clone()
}

/// Node `ChainSpec` extensions.
///
/// Additional parameters for some Substrate core modules,
/// customizable from the chain spec.
#[derive(Default, Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    /// Block numbers with known hashes.
    pub fork_blocks: sc_client_api::ForkBlocks<Block>,
    /// Known bad block hashes.
    pub bad_blocks: sc_client_api::BadBlocks<Block>,
    /// The light sync state extension used by the sync-state rpc.
    pub light_sync_state: sc_sync_state_rpc::LightSyncStateExtension,
}

/// Specialized `ChainSpec`.
pub type ChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig, Extensions>;

fn session_keys(
    grandpa: GrandpaId,
    babe: BabeId,
    im_online: ImOnlineId,
    authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
    SessionKeys { grandpa, babe, im_online, authority_discovery }
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{seed}"), None)
        .expect("static values are valid; qed")
        .public()
}

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate stash, controller and session key from seed
pub fn authority_keys_from_seed(
    seed: &str,
) -> (AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId) {
    (
        get_account_id_from_seed::<sr25519::Public>(&format!("{seed}//stash")),
        get_account_id_from_seed::<sr25519::Public>(seed),
        get_from_seed::<GrandpaId>(seed),
        get_from_seed::<BabeId>(seed),
        get_from_seed::<ImOnlineId>(seed),
        get_from_seed::<AuthorityDiscoveryId>(seed),
    )
}

/// Accepted measurement values for TDX attestation
pub type MeasurementValues = Vec<BoundedVec<u8, ConstU32<32>>>;
