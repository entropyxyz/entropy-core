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
use sp_runtime::traits::{IdentifyAccount, Verify};

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
            super::hex!["e0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876"].into();

    /// The `DEFAULT_BOB_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "where sight patient orphan general short empower hope party hurt month voice"
    pub static ref BOB: sp_runtime::AccountId32  =
            super::hex!["2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f"].into();

    /// The `DEFAULT_CHARLIE_MNEMONIC` is used to derive the following `AccountId`.
    /// Mnemonic: "lake carry still awful point mention bike category tornado plate brass lock"
    pub static ref CHARLIE: sp_runtime::AccountId32  =
            super::hex!["14d223daeec68671f07298c66c9458980a48bb89fb8a85d5df31131acad8d611"].into();

    /// Not sure what mnemonic is used to derive the following `AccountId`.
    /// Mnemonic: "????"
    pub static ref DAVE: sp_runtime::AccountId32  =
            super::hex!["5212c5f562f4a43b89caadfeb9f5896dd4084700afa72aa55ca306d689523f3a"].into();

    }
}

/// The X25519 public key used by the Threshold Signature Scheme servers (TSS) to encrypt messages
/// between TSS servers.
pub mod tss_x25519_public_key {
    /// The `DEFAULT_ALICE_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
    pub const ALICE: [u8; 32] = [
        10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155, 124, 195, 141, 148,
        249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247, 58, 34,
    ];

    /// The `DEFAULT_BOB_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "where sight patient orphan general short empower hope party hurt month voice"
    pub const BOB: [u8; 32] = [
        225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245, 89, 36, 170, 169,
        181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136, 102, 10,
    ];

    /// The `DEFAULT_CHARLIE_MNEMONIC` is used to derive the public key.
    /// Mnemonic: "lake carry still awful point mention bike category tornado plate brass lock"
    pub const CHARLIE: [u8; 32] = [
        245, 222, 99, 201, 89, 227, 119, 236, 142, 217, 74, 171, 58, 162, 140, 165, 7, 104, 210,
        36, 196, 227, 208, 254, 175, 100, 226, 50, 239, 84, 141, 13,
    ];

    /// Not sure what mnemonic is used to derive the following public key.
    /// Mnemonic: "????"
    pub const EVE: [u8; 32] = [
        142, 113, 91, 59, 177, 104, 208, 23, 219, 170, 47, 145, 200, 139, 188, 28, 14, 199, 116,
        86, 193, 144, 10, 18, 74, 157, 138, 202, 115, 99, 229, 55,
    ];
}

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
