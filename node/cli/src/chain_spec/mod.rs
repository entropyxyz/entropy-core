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

#![allow(dead_code)]

pub mod dev;

pub use entropy_runtime::RuntimeGenesisConfig;
use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AuthorityDiscoveryConfig, BabeConfig,
    BalancesConfig, Block, CouncilConfig, DemocracyConfig, ElectionsConfig, GrandpaConfig,
    ImOnlineConfig, IndicesConfig, MaxNominations, RelayerConfig, SessionConfig, SessionKeys,
    StakerStatus, StakingConfig, StakingExtensionConfig, SudoConfig, SystemConfig,
    TechnicalCommitteeConfig,
};
use entropy_shared::ValidatorInfo;
use grandpa_primitives::AuthorityId as GrandpaId;
use hex_literal::hex;
pub use node_primitives::{AccountId, Balance, Signature};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_chain_spec::{ChainSpecExtension, Properties};
use sc_service::ChainType;
use sc_telemetry::TelemetryEndpoints;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    Perbill,
};

use crate::{
    admin,
    endowed_accounts::{endowed_accounts_dev, endowed_accounts_devnet},
};
type AccountPublic = <Signature as Verify>::Signer;

const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";
const DEFAULT_PROTOCOL_ID: &str = "Entropy"; // TODO finalize

lazy_static::lazy_static! {
    // TODO: Make this an AccountId32
    pub static ref ALICE_TSS_ACCOUNT_ID: [u8; 32] =
            hex!["e0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876"];

    pub static ref BOB_TSS_ACCOUNT_ID: [u8; 32] =
            hex!["2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f"];
}

// TODO: finalize
fn entropy_props() -> Properties {
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

/// Staging testnet config.
pub fn staging_testnet_config() -> ChainSpec {
    let boot_nodes = vec![];
    ChainSpec::from_genesis(
        "Staging Testnet",
        "staging_testnet",
        ChainType::Live,
        admin::staging_testnet_config_genesis,
        boot_nodes,
        Some(
            TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
                .expect("Staging telemetry url is valid; qed"),
        ),
        None,
        None,
        None,
        Default::default(),
    )
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

/// Helper function to create RuntimeGenesisConfig for testing
pub fn testnet_genesis(
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        GrandpaId,
        BabeId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )>,
    initial_nominators: Vec<AccountId>,
    root_key: AccountId,
) -> RuntimeGenesisConfig {
    let mut endowed_accounts = endowed_accounts_dev();
    // endow all authorities and nominators.
    initial_authorities.iter().map(|x| &x.0).chain(initial_nominators.iter()).for_each(|x| {
        if !endowed_accounts.contains(x) {
            endowed_accounts.push(x.clone())
        }
    });

    // stakers: all validators and nominators.
    let mut rng = rand::thread_rng();
    let stakers = initial_authorities
        .iter()
        .map(|x| (x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator))
        .chain(initial_nominators.iter().map(|x| {
            use rand::{seq::SliceRandom, Rng};
            let limit = (MaxNominations::get() as usize).min(initial_authorities.len());
            let count = rng.gen::<usize>() % limit;
            let nominations = initial_authorities
                .as_slice()
                .choose_multiple(&mut rng, count)
                .map(|choice| choice.0.clone())
                .collect::<Vec<_>>();
            (x.clone(), x.clone(), STASH, StakerStatus::Nominator(nominations))
        }))
        .collect::<Vec<_>>();

    let num_endowed_accounts = endowed_accounts.len();

    const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
    const STASH: Balance = ENDOWMENT / 1000;

    RuntimeGenesisConfig {
        system: SystemConfig { code: wasm_binary_unwrap().to_vec(), ..Default::default() },
        balances: BalancesConfig {
            balances: endowed_accounts.iter().cloned().map(|x| (x, ENDOWMENT)).collect(),
        },
        indices: IndicesConfig { indices: vec![] },
        session: SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        session_keys(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()),
                    )
                })
                .collect::<Vec<_>>(),
        },
        staking: StakingConfig {
            validator_count: initial_authorities.len() as u32,
            minimum_validator_count: 0,
            invulnerables: vec![],
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        staking_extension: StakingExtensionConfig {
            threshold_servers: vec![
                (
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    (
                        // Seed phrase: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
                        (*ALICE_TSS_ACCOUNT_ID).into(),
                        *entropy_shared::ALICE_X25519_PUBLIC_KEY,
                        "127.0.0.1:3001".as_bytes().to_vec(),
                    ),
                ),
                (
                    get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    (
                        // Seed phrase: "where sight patient orphan general short empower hope party hurt month voice"
                        (*BOB_TSS_ACCOUNT_ID).into(),
                        *entropy_shared::BOB_X25519_PUBLIC_KEY,
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
            ],
            signing_groups: vec![
                (0, vec![get_account_id_from_seed::<sr25519::Public>("Alice//stash")]),
                (1, vec![get_account_id_from_seed::<sr25519::Public>("Bob//stash")]),
            ],
            proactive_refresh_validators: vec![],
        },
        democracy: DemocracyConfig::default(),
        elections: ElectionsConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        council: CouncilConfig::default(),
        technical_committee: TechnicalCommitteeConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            phantom: Default::default(),
        },
        sudo: SudoConfig { key: Some(root_key) },
        babe: BabeConfig {
            authorities: vec![],
            epoch_config: Some(entropy_runtime::BABE_GENESIS_EPOCH_CONFIG),
            ..Default::default()
        },
        im_online: ImOnlineConfig { keys: vec![] },
        authority_discovery: AuthorityDiscoveryConfig { keys: vec![], ..Default::default() },
        grandpa: GrandpaConfig { authorities: vec![], ..Default::default() },
        technical_membership: Default::default(),
        treasury: Default::default(),
        relayer: RelayerConfig {
            registered_accounts: vec![
                (get_account_id_from_seed::<sr25519::Public>("Dave"), 0, None),
                (
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    1,
                    Some([
                        28, 63, 144, 84, 78, 147, 195, 214, 190, 234, 111, 101, 117, 133, 9, 198,
                        96, 96, 76, 140, 152, 251, 255, 28, 167, 38, 157, 185, 192, 42, 201, 82,
                    ]),
                ),
                (get_account_id_from_seed::<sr25519::Public>("Ferdie"), 2, None),
            ],
        },
        vesting: Default::default(),
        transaction_storage: Default::default(),
        transaction_payment: Default::default(),
        nomination_pools: Default::default(),
    }
}

/// Generates a [Substrate chain spec] for use during "[local devnet]"
/// operation to ensure proper startup of the network.
///
/// Poper startup means informing each of the [chain nodes] that make
/// up the initial network participants of each other's reachable
/// network addresses, such thtat they can all find communicate with
/// one another, along with other information such as initial funding
/// balances, and the initial ("genesis") values of certain key data.
/// This network-wide, shared data is termed "on-chain storage." The
/// generated chain spec is thus the genesis data (initial values) of
/// the on-chain storage for the network.
///
/// [Substrate chain spec]: https://docs.substrate.io/build/chain-spec/
/// [local devnet]: https://github.com/entropyxyz/meta/wiki/Local-devnet
/// [chain nodes]: https://github.com/entropyxyz/meta/wiki/Glossary#chain-node
pub fn local_devnet_genesis(
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        GrandpaId,
        BabeId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )>,
    initial_nominators: Vec<AccountId>,
    root_key: AccountId,
) -> RuntimeGenesisConfig {
    let mut endowed_accounts = endowed_accounts_dev();
    // endow all authorities and nominators.
    initial_authorities.iter().map(|x| &x.0).chain(initial_nominators.iter()).for_each(|x| {
        if !endowed_accounts.contains(x) {
            endowed_accounts.push(x.clone())
        }
    });

    // stakers: all validators and nominators.
    let mut rng = rand::thread_rng();
    let stakers = initial_authorities
        .iter()
        .map(|x| (x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator))
        .chain(initial_nominators.iter().map(|x| {
            use rand::{seq::SliceRandom, Rng};
            let limit = (MaxNominations::get() as usize).min(initial_authorities.len());
            let count = rng.gen::<usize>() % limit;
            let nominations = initial_authorities
                .as_slice()
                .choose_multiple(&mut rng, count)
                .map(|choice| choice.0.clone())
                .collect::<Vec<_>>();
            (x.clone(), x.clone(), STASH, StakerStatus::Nominator(nominations))
        }))
        .collect::<Vec<_>>();

    let num_endowed_accounts = endowed_accounts.len();

    const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
    const STASH: Balance = ENDOWMENT / 1000;

    RuntimeGenesisConfig {
        system: SystemConfig { code: wasm_binary_unwrap().to_vec(), ..Default::default() },
        balances: BalancesConfig {
            balances: endowed_accounts.iter().cloned().map(|x| (x, ENDOWMENT)).collect(),
        },
        indices: IndicesConfig { indices: vec![] },
        session: SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        session_keys(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()),
                    )
                })
                .collect::<Vec<_>>(),
        },
        staking: StakingConfig {
            validator_count: initial_authorities.len() as u32,
            minimum_validator_count: 0,
            invulnerables: vec![],
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        staking_extension: StakingExtensionConfig {
            threshold_servers: vec![
                (
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    (
                        // Seed phrase: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
                        hex!["e0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876"]
                            .into(),
                        [
                            10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155,
                            124, 195, 141, 148, 249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247,
                            58, 34,
                        ],
                        "alice-tss-server:3001".as_bytes().to_vec(),
                    ),
                ),
                (
                    get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    (
                        // Seed phrase: "where sight patient orphan general short empower hope party hurt month voice"
                        hex!["2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f"]
                            .into(),
                        [
                            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245,
                            89, 36, 170, 169, 181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136,
                            102, 10,
                        ],
                        "bob-tss-server:3002".as_bytes().to_vec(),
                    ),
                ),
            ],
            signing_groups: vec![
                (0, vec![get_account_id_from_seed::<sr25519::Public>("Alice//stash")]),
                (1, vec![get_account_id_from_seed::<sr25519::Public>("Bob//stash")]),
            ],
            proactive_refresh_validators: vec![],
        },
        democracy: DemocracyConfig::default(),
        elections: ElectionsConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        council: CouncilConfig::default(),
        technical_committee: TechnicalCommitteeConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            phantom: Default::default(),
        },
        sudo: SudoConfig { key: Some(root_key) },
        babe: BabeConfig {
            authorities: vec![],
            epoch_config: Some(entropy_runtime::BABE_GENESIS_EPOCH_CONFIG),
            ..Default::default()
        },
        im_online: ImOnlineConfig { keys: vec![] },
        authority_discovery: AuthorityDiscoveryConfig { keys: vec![], ..Default::default() },
        grandpa: GrandpaConfig { authorities: vec![], ..Default::default() },
        technical_membership: Default::default(),
        treasury: Default::default(),
        relayer: RelayerConfig {
            registered_accounts: vec![
                (get_account_id_from_seed::<sr25519::Public>("Dave"), 0, None),
                (
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    1,
                    Some([
                        28, 63, 144, 84, 78, 147, 195, 214, 190, 234, 111, 101, 117, 133, 9, 198,
                        96, 96, 76, 140, 152, 251, 255, 28, 167, 38, 157, 185, 192, 42, 201, 82,
                    ]),
                ),
                (get_account_id_from_seed::<sr25519::Public>("Ferdie"), 2, None),
            ],
        },
        vesting: Default::default(),
        transaction_storage: Default::default(),
        transaction_payment: Default::default(),
        nomination_pools: Default::default(),
    }
}

/// Helper function to create GenesisConfig for testing
pub fn devnet_genesis(
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        GrandpaId,
        BabeId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )>,
    initial_nominators: Vec<AccountId>,
    root_key: AccountId,
) -> RuntimeGenesisConfig {
    let mut endowed_accounts = endowed_accounts_devnet();
    // endow all authorities and nominators.
    initial_authorities.iter().map(|x| &x.0).chain(initial_nominators.iter()).for_each(|x| {
        if !endowed_accounts.contains(x) {
            endowed_accounts.push(x.clone())
        }
    });
    if !endowed_accounts.contains(&root_key) {
        endowed_accounts.push(root_key.clone())
    }
    // stakers: all validators and nominators.
    let mut rng = rand::thread_rng();
    let stakers = initial_authorities
        .iter()
        .map(|x| (x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator))
        .chain(initial_nominators.iter().map(|x| {
            use rand::{seq::SliceRandom, Rng};
            let limit = (MaxNominations::get() as usize).min(initial_authorities.len());
            let count = rng.gen::<usize>() % limit;
            let nominations = initial_authorities
                .as_slice()
                .choose_multiple(&mut rng, count)
                .map(|choice| choice.0.clone())
                .collect::<Vec<_>>();
            (x.clone(), x.clone(), STASH, StakerStatus::Nominator(nominations))
        }))
        .collect::<Vec<_>>();

    let num_endowed_accounts = endowed_accounts.len();

    const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
    const STASH: Balance = ENDOWMENT / 1000;

    RuntimeGenesisConfig {
        system: SystemConfig { code: wasm_binary_unwrap().to_vec(), ..Default::default() },
        balances: BalancesConfig {
            balances: endowed_accounts.iter().cloned().map(|x| (x, ENDOWMENT)).collect(),
        },
        indices: IndicesConfig { indices: vec![] },
        session: SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        session_keys(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()),
                    )
                })
                .collect::<Vec<_>>(),
        },
        staking: StakingConfig {
            validator_count: initial_authorities.len() as u32,
            minimum_validator_count: 0,
            invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        staking_extension: StakingExtensionConfig {
            threshold_servers: vec![],
            signing_groups: vec![],
            proactive_refresh_validators: vec![],
        },
        democracy: DemocracyConfig::default(),
        elections: ElectionsConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        council: CouncilConfig::default(),
        technical_committee: TechnicalCommitteeConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            phantom: Default::default(),
        },
        sudo: SudoConfig { key: Some(root_key) },
        babe: BabeConfig {
            authorities: vec![],
            epoch_config: Some(entropy_runtime::BABE_GENESIS_EPOCH_CONFIG),
            ..Default::default()
        },
        im_online: ImOnlineConfig { keys: vec![] },
        authority_discovery: AuthorityDiscoveryConfig { keys: vec![], ..Default::default() },
        grandpa: GrandpaConfig { authorities: vec![], ..Default::default() },
        technical_membership: Default::default(),
        treasury: Default::default(),
        relayer: RelayerConfig { registered_accounts: vec![] },
        vesting: Default::default(),
        transaction_storage: Default::default(),
        transaction_payment: Default::default(),
        nomination_pools: Default::default(),
    }
}

/// Helper function to create RuntimeGenesisConfig for testing
pub fn testing(
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        GrandpaId,
        BabeId,
        ImOnlineId,
        AuthorityDiscoveryId,
    )>,
    initial_nominators: Vec<AccountId>,
    root_key: AccountId,
) -> RuntimeGenesisConfig {
    let mut endowed_accounts = endowed_accounts_dev();
    // endow all authorities and nominators.
    initial_authorities.iter().map(|x| &x.0).chain(initial_nominators.iter()).for_each(|x| {
        if !endowed_accounts.contains(x) {
            endowed_accounts.push(x.clone())
        }
    });

    // stakers: all validators and nominators.
    let mut rng = rand::thread_rng();
    let stakers = initial_authorities
        .iter()
        .map(|x| (x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator))
        .chain(initial_nominators.iter().map(|x| {
            use rand::{seq::SliceRandom, Rng};
            let limit = (MaxNominations::get() as usize).min(initial_authorities.len());
            let count = rng.gen::<usize>() % limit;
            let nominations = initial_authorities
                .as_slice()
                .choose_multiple(&mut rng, count)
                .map(|choice| choice.0.clone())
                .collect::<Vec<_>>();
            (x.clone(), x.clone(), STASH, StakerStatus::Nominator(nominations))
        }))
        .collect::<Vec<_>>();

    let num_endowed_accounts = endowed_accounts.len();

    const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
    const STASH: Balance = ENDOWMENT / 1000;

    RuntimeGenesisConfig {
        system: SystemConfig { code: wasm_binary_unwrap().to_vec(), ..Default::default() },
        balances: BalancesConfig {
            balances: endowed_accounts.iter().cloned().map(|x| (x, ENDOWMENT)).collect(),
        },
        indices: IndicesConfig { indices: vec![] },
        session: SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        session_keys(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()),
                    )
                })
                .collect::<Vec<_>>(),
        },
        staking: StakingConfig {
            validator_count: initial_authorities.len() as u32,
            minimum_validator_count: 0,
            invulnerables: vec![],
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        staking_extension: StakingExtensionConfig {
            threshold_servers: vec![
                (
                    get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    (
                        // Seed phrase: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
                        hex!["e0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876"]
                            .into(),
                        [
                            10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155,
                            124, 195, 141, 148, 249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247,
                            58, 34,
                        ],
                        "127.0.0.1:3001".as_bytes().to_vec(),
                    ),
                ),
                (
                    get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    (
                        // Seed phrase: "where sight patient orphan general short empower hope party hurt month voice"
                        hex!["2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f"]
                            .into(),
                        [
                            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245,
                            89, 36, 170, 169, 181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136,
                            102, 10,
                        ],
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
                (
                    // Seed phrase: "lake carry still awful point mention bike category tornado plate brass lock"
                    get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                    (
                        hex!["14d223daeec68671f07298c66c9458980a48bb89fb8a85d5df31131acad8d611"]
                            .into(),
                        [
                            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245,
                            89, 36, 170, 169, 181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136,
                            102, 10,
                        ],
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
                (
                    get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                    (
                        hex!["5212c5f562f4a43b89caadfeb9f5896dd4084700afa72aa55ca306d689523f3a"]
                            .into(),
                        [
                            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245,
                            89, 36, 170, 169, 181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136,
                            102, 10,
                        ],
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
            ],
            signing_groups: vec![
                (
                    0,
                    vec![
                        get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                        get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                    ],
                ),
                (1, vec![get_account_id_from_seed::<sr25519::Public>("Bob//stash")]),
            ],
            proactive_refresh_validators: vec![
                ValidatorInfo {
                    tss_account: hex![
                        "e0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876"
                    ]
                    .into(),
                    ip_address: "127.0.0.1:3001".as_bytes().to_vec(),
                    x25519_public_key: [
                        10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155, 124,
                        195, 141, 148, 249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247, 58, 34,
                    ],
                },
                ValidatorInfo {
                    tss_account: hex![
                        "2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f"
                    ]
                    .into(),
                    ip_address: "127.0.0.1:3002".as_bytes().to_vec(),
                    x25519_public_key: [
                        225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245, 89,
                        36, 170, 169, 181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136, 102, 10,
                    ],
                },
            ],
        },
        democracy: DemocracyConfig::default(),
        elections: ElectionsConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        council: CouncilConfig::default(),
        technical_committee: TechnicalCommitteeConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            phantom: Default::default(),
        },
        sudo: SudoConfig { key: Some(root_key) },
        babe: BabeConfig {
            authorities: vec![],
            epoch_config: Some(entropy_runtime::BABE_GENESIS_EPOCH_CONFIG),
            ..Default::default()
        },
        im_online: ImOnlineConfig { keys: vec![] },
        authority_discovery: AuthorityDiscoveryConfig { keys: vec![], ..Default::default() },
        grandpa: GrandpaConfig { authorities: vec![], ..Default::default() },
        technical_membership: Default::default(),
        treasury: Default::default(),
        relayer: RelayerConfig {
            registered_accounts: vec![
                (get_account_id_from_seed::<sr25519::Public>("Dave"), 0, None),
                (
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    1,
                    Some([
                        28, 63, 144, 84, 78, 147, 195, 214, 190, 234, 111, 101, 117, 133, 9, 198,
                        96, 96, 76, 140, 152, 251, 255, 28, 167, 38, 157, 185, 192, 42, 201, 82,
                    ]),
                ),
                (get_account_id_from_seed::<sr25519::Public>("Ferdie"), 2, None),
            ],
        },
        vesting: Default::default(),
        transaction_storage: Default::default(),
        transaction_payment: Default::default(),
        nomination_pools: Default::default(),
    }
}

/// Local devnet configuration, used when invoked with the
/// `--chain local-devnet` option.
pub fn local_devnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Entropy Local Devnet",
        "EDevLocal",
        ChainType::Development,
        admin::local_devnet_config_genesis,
        vec![],
        None,
        None,
        None,
        None,
        Default::default(),
    )
}

/// Testing config (single validator Alice)
pub fn testing_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Testing",
        "test",
        ChainType::Development,
        admin::testing_config_genesis,
        vec![],
        None,
        None,
        None,
        None,
        Default::default(),
    )
}

/// Development config (single validator Alice)
pub fn testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "EntropyTestnet",
        "ETest",
        ChainType::Live,
        admin::testnet_config_genesis,
        vec![],
        Some(
            TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
                .expect("Staging telemetry url is valid; qed"),
        ),
        Some(DEFAULT_PROTOCOL_ID),
        None,
        Some(entropy_props()),
        Default::default(),
    )
}

fn local_testnet_genesis() -> RuntimeGenesisConfig {
    testnet_genesis(
        vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
        vec![],
        get_account_id_from_seed::<sr25519::Public>("Alice"),
    )
}

/// Local testnet config (multivalidator Alice + Bob)
pub fn local_testnet_config() -> ChainSpec {
    ChainSpec::from_genesis(
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        local_testnet_genesis,
        vec![],
        None,
        None,
        None,
        None,
        Default::default(),
    )
}
