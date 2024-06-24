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

use crate::chain_spec::{get_account_id_from_seed, ChainSpec};
use crate::endowed_accounts::endowed_accounts_dev;

use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AuthorityDiscoveryConfig, BabeConfig,
    BalancesConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig, IndicesConfig, MaxNominations,
    ParametersConfig, ProgramsConfig, RegistryConfig, SessionConfig, StakerStatus, StakingConfig,
    StakingExtensionConfig, SudoConfig, TechnicalCommitteeConfig,
};
use entropy_runtime::{AccountId, Balance};
use entropy_shared::{
    X25519PublicKey as TssX25519PublicKey, DAVE_VERIFYING_KEY, DEVICE_KEY_AUX_DATA_TYPE,
    DEVICE_KEY_CONFIG_TYPE, DEVICE_KEY_HASH, DEVICE_KEY_PROXY, EVE_VERIFYING_KEY,
    FERDIE_VERIFYING_KEY, INITIAL_MAX_INSTRUCTIONS_PER_PROGRAM,
};
use grandpa_primitives::AuthorityId as GrandpaId;
use itertools::Itertools;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::ChainType;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::sr25519;
use sp_runtime::{BoundedVec, Perbill};

const SIGNING_GROUPS: usize = 2;

pub fn devnet_local_large_initial_tss_servers(
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String)> {
    let alice = (
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_x25519_public_key::ALICE,
        "alice-tss-server:3001".to_string(),
    );

    let bob = (
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_x25519_public_key::BOB,
        "bob-tss-server:3002".to_string(),
    );
    let dave = (
        crate::chain_spec::tss_account_id::DAVE.clone(),
        crate::chain_spec::tss_x25519_public_key::DAVE,
        "dave-tss-server:3003".to_string(),
    );
    let eve = (
        crate::chain_spec::tss_account_id::EVE.clone(),
        crate::chain_spec::tss_x25519_public_key::EVE_TSS,
        "eve-tss-server:3004".to_string(),
    );

    vec![alice, bob, dave, eve]
}

pub fn devnet_local_two_node_docker_initial_tss_servers(
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String)> {
    let alice = (
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_x25519_public_key::ALICE,
        "alice-tss-server:3001".to_string(),
    );

    let bob = (
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_x25519_public_key::BOB,
        "bob-tss-server:3002".to_string(),
    );

    vec![alice, bob]
}

pub fn devnet_local_two_node_initial_tss_servers(
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String)> {
    let alice = (
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_x25519_public_key::ALICE,
        "127.0.0.1:3001".to_string(),
    );

    let bob = (
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_x25519_public_key::BOB,
        "127.0.0.1:3002".to_string(),
    );

    vec![alice, bob]
}

// The configuration used for a local testnet network spun up using the `docker-compose` setup
/// provided in this repository.
///
/// This configuration matches the same setup as the `testnet`, with the exception that is uses
/// four well-known accounts (Alice Bob Dave and Eve) as the authorities.
pub fn devnet_local_config_large() -> crate::chain_spec::ChainSpec {
    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("Entropy Devnet Local Large")
        .with_id("entropy_devnet_local_four_nodes")
        .with_chain_type(ChainType::Development)
        .with_genesis_config_patch(development_genesis_config(
            vec![
                crate::chain_spec::authority_keys_from_seed("Alice"),
                crate::chain_spec::authority_keys_from_seed("Bob"),
                crate::chain_spec::authority_keys_from_seed("Dave"),
                crate::chain_spec::authority_keys_from_seed("Eve"),
            ],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            devnet_local_large_initial_tss_servers(),
        ))
        .with_properties(crate::chain_spec::entropy_properties())
        .build()
}
/// The configuration used for development.
///
/// Since Entropy requires at least two signing groups to work properly we spin up this network with
/// two validators, Alice and Bob.
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
            ],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            devnet_local_two_node_initial_tss_servers(),
        ))
        .build()
}

/// The configuration used for a local development network spun up with the `docker-compose` setup
/// provided in this repository.
///
/// Since Entropy requires at least two signing groups to work properly we spin up this network with
/// two validators, Alice and Bob.
pub fn devnet_local_config() -> crate::chain_spec::ChainSpec {
    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("Devnet Local")
        .with_id("devnet_local")
        .with_properties(crate::chain_spec::entropy_properties())
        .with_chain_type(ChainType::Development)
        .with_genesis_config_patch(development_genesis_config(
            vec![
                crate::chain_spec::authority_keys_from_seed("Alice"),
                crate::chain_spec::authority_keys_from_seed("Bob"),
            ],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            devnet_local_two_node_docker_initial_tss_servers(),
        ))
        .build()
}

pub fn development_genesis_config(
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
    initial_tss_servers: Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String)>,
) -> serde_json::Value {
    // Note that any endowed_accounts added here will be included in the `elections` and
    // `technical_committee` genesis configs. If you don't want that, don't push those accounts to
    // this list.
    let mut endowed_accounts = vec![];

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

    serde_json::json!({
        "balances": BalancesConfig {
            balances: endowed_accounts
                        .iter()
                        .chain(endowed_accounts_dev().iter())
                        .cloned()
                        .map(|x| (x, ENDOWMENT))
                        .unique()
                        .collect(),
        },
        "indices": IndicesConfig { indices: vec![] },
        "session": SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        crate::chain_spec::session_keys(
                            x.2.clone(),
                            x.3.clone(),
                            x.4.clone(),
                            x.5.clone(),
                        ),
                    )
                })
                .collect::<Vec<_>>(),
        },
        "staking": StakingConfig {
            validator_count: initial_authorities.len() as u32,
            minimum_validator_count: 0,
            invulnerables: vec![],
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        "stakingExtension": StakingExtensionConfig {
            threshold_servers: initial_authorities
                .iter()
                .zip(initial_tss_servers.iter())
                .map(|(auth, tss)| {
                    (auth.0.clone(), (tss.0.clone(), tss.1, tss.2.as_bytes().to_vec()))
                })
                .collect::<Vec<_>>(),
            // We place all Stash accounts into the specified number of signing groups
            signing_groups: initial_authorities
                .iter()
                .map(|x| x.0.clone())
                .collect::<Vec<_>>()
                .as_slice()
                .chunks((initial_authorities.len() + SIGNING_GROUPS - 1) / SIGNING_GROUPS)
                .enumerate()
                .map(|(i, v)| (i as u8, v.to_vec()))
                .collect::<Vec<_>>(),
            proactive_refresh_data: (vec![], vec![]),
        },
        "elections": ElectionsConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        "technicalCommittee": TechnicalCommitteeConfig  {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 2)
                .cloned()
                .collect(),
            phantom: Default::default(),
        },
        "sudo": SudoConfig { key: Some(root_key.clone()) },
        "babe": BabeConfig {
            authorities: vec![],
            epoch_config: Some(entropy_runtime::BABE_GENESIS_EPOCH_CONFIG),
            ..Default::default()
        },
        "imOnline": ImOnlineConfig { keys: vec![] },
        "authorityDiscovery": AuthorityDiscoveryConfig { keys: vec![], ..Default::default() },
        "grandpa": GrandpaConfig  { authorities: vec![], ..Default::default() },
        "registry": RegistryConfig {
            registered_accounts: vec![
                (
                    get_account_id_from_seed::<sr25519::Public>("Dave"),
                    0,
                    None,
                    BoundedVec::try_from(DAVE_VERIFYING_KEY.to_vec()).unwrap(),
                ),
                (
                    get_account_id_from_seed::<sr25519::Public>("Eve"),
                    1,
                    Some(crate::chain_spec::tss_x25519_public_key::EVE),
                    BoundedVec::try_from(EVE_VERIFYING_KEY.to_vec()).unwrap(),
                ),
                (
                    get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                    2,
                    None,
                    BoundedVec::try_from(FERDIE_VERIFYING_KEY.to_vec()).unwrap(),
                ),
            ],
        },
        "parameters": ParametersConfig {
            request_limit: 20,
            max_instructions_per_programs: INITIAL_MAX_INSTRUCTIONS_PER_PROGRAM,
            ..Default::default()
        },
        "programs": ProgramsConfig {
            inital_programs: vec![(
                *DEVICE_KEY_HASH,
                DEVICE_KEY_PROXY.to_vec(),
                (*DEVICE_KEY_CONFIG_TYPE.clone()).to_vec(),
                (*DEVICE_KEY_AUX_DATA_TYPE.clone()).to_vec(),
                root_key,
                10,
            )],
        },
    })
}
