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

use crate::chain_spec::{get_account_id_from_seed, provisioning_certification_key, ChainSpec};
use crate::endowed_accounts::endowed_accounts_dev;

use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AttestationConfig, AuthorityDiscoveryConfig,
    BabeConfig, BalancesConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig, IndicesConfig,
    MaxNominations, ParametersConfig, ProgramsConfig, SessionConfig, StakerStatus, StakingConfig,
    StakingExtensionConfig, SudoConfig, TechnicalCommitteeConfig,
};
use entropy_runtime::{AccountId, Balance};
use entropy_shared::{
    BoundedVecEncodedVerifyingKey, X25519PublicKey as TssX25519PublicKey, DEVICE_KEY_AUX_DATA_TYPE,
    DEVICE_KEY_CONFIG_TYPE, DEVICE_KEY_HASH, DEVICE_KEY_PROXY,
    INITIAL_MAX_INSTRUCTIONS_PER_PROGRAM, SIGNER_THRESHOLD, TOTAL_SIGNERS,
};
use grandpa_primitives::AuthorityId as GrandpaId;
use itertools::Itertools;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::ChainType;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{sr25519, ByteArray};
use sp_runtime::{BoundedVec, Perbill};

pub fn devnet_four_node_initial_tss_servers(
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String, BoundedVecEncodedVerifyingKey)> {
    let alice = (
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_x25519_public_key::ALICE,
        "127.0.0.1:3001".to_string(),
        provisioning_certification_key::ALICE.clone(),
    );

    let bob = (
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_x25519_public_key::BOB,
        "127.0.0.1:3002".to_string(),
        provisioning_certification_key::BOB.clone(),
    );

    let charlie = (
        crate::chain_spec::tss_account_id::CHARLIE.clone(),
        crate::chain_spec::tss_x25519_public_key::CHARLIE,
        "127.0.0.1:3003".to_string(),
        provisioning_certification_key::CHARLIE.clone(),
    );

    let dave = (
        crate::chain_spec::tss_account_id::DAVE.clone(),
        crate::chain_spec::tss_x25519_public_key::DAVE,
        "127.0.0.1:3004".to_string(),
        provisioning_certification_key::DAVE.clone(),
    );

    vec![alice, bob, charlie, dave]
}

pub fn devnet_local_docker_four_node_initial_tss_servers(
) -> Vec<(sp_runtime::AccountId32, TssX25519PublicKey, String, BoundedVecEncodedVerifyingKey)> {
    let alice = (
        crate::chain_spec::tss_account_id::ALICE.clone(),
        crate::chain_spec::tss_x25519_public_key::ALICE,
        "alice-tss-server:3001".to_string(),
        provisioning_certification_key::ALICE.clone(),
    );

    let bob = (
        crate::chain_spec::tss_account_id::BOB.clone(),
        crate::chain_spec::tss_x25519_public_key::BOB,
        "bob-tss-server:3002".to_string(),
        provisioning_certification_key::BOB.clone(),
    );

    let charlie = (
        crate::chain_spec::tss_account_id::CHARLIE.clone(),
        crate::chain_spec::tss_x25519_public_key::CHARLIE,
        "charlie-tss-server:3003".to_string(),
        provisioning_certification_key::CHARLIE.clone(),
    );

    let dave = (
        crate::chain_spec::tss_account_id::DAVE.clone(),
        crate::chain_spec::tss_x25519_public_key::DAVE,
        "dave-tss-server:3004".to_string(),
        provisioning_certification_key::DAVE.clone(),
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
            devnet_four_node_initial_tss_servers(),
        ))
        .build()
}

/// The configuration used for a local development network spun up with the `docker-compose` setup
/// provided in this repository.
///
/// Since Entropy requires at two-of-three threshold setup, and requires an additional relayer node,
/// we spin up four validators: Alice, Bob, Charlie and Dave.
pub fn devnet_local_four_node_config() -> crate::chain_spec::ChainSpec {
    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("Devnet Local")
        .with_id("devnet_local")
        .with_properties(crate::chain_spec::entropy_properties())
        .with_chain_type(ChainType::Development)
        .with_genesis_config_patch(development_genesis_config(
            vec![
                crate::chain_spec::authority_keys_from_seed("Alice"),
                crate::chain_spec::authority_keys_from_seed("Bob"),
                crate::chain_spec::authority_keys_from_seed("Charlie"),
                crate::chain_spec::authority_keys_from_seed("Dave"),
            ],
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            devnet_local_docker_four_node_initial_tss_servers(),
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
    initial_tss_servers: Vec<(
        sp_runtime::AccountId32,
        TssX25519PublicKey,
        String,
        BoundedVecEncodedVerifyingKey,
    )>,
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
                    (auth.0.clone(), (tss.0.clone(), tss.1, tss.2.as_bytes().to_vec(), tss.3.clone()))
                })
                .collect::<Vec<_>>(),
            proactive_refresh_data: (vec![], vec![]),
            mock_signer_rotate: (false, vec![], vec![]),
            jump_start_state: None,
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
        "parameters": ParametersConfig {
            request_limit: 20,
            max_instructions_per_programs: INITIAL_MAX_INSTRUCTIONS_PER_PROGRAM,
            total_signers: TOTAL_SIGNERS,
            threshold: SIGNER_THRESHOLD,
            accepted_mrtd_values: vec![
                BoundedVec::try_from([0; 48].to_vec()).unwrap(),
                BoundedVec::try_from([1; 48].to_vec()).unwrap(),
            ],
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
        "attestation": AttestationConfig {
            initial_attestation_requests: vec![(3, vec![crate::chain_spec::tss_account_id::ALICE.to_raw_vec()])],
            initial_pending_attestations: vec![(crate::chain_spec::tss_account_id::ALICE.clone(), [0; 32])],
        },
    })
}
