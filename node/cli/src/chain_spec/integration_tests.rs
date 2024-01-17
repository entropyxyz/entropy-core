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

use crate::endowed_accounts::endowed_accounts_dev;
pub use entropy_runtime::RuntimeGenesisConfig;
use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AuthorityDiscoveryConfig, BabeConfig,
    BalancesConfig, CouncilConfig, DemocracyConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig,
    IndicesConfig, MaxNominations, RelayerConfig, SessionConfig, StakerStatus, StakingConfig,
    StakingExtensionConfig, SudoConfig, SystemConfig, TechnicalCommitteeConfig,
};
use grandpa_primitives::AuthorityId as GrandpaId;
use hex_literal::hex;
pub use node_primitives::{AccountId, Balance, Signature};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::ChainType;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::sr25519;
use sp_runtime::Perbill;

/// Testing config (single validator Alice)
pub fn integration_tests_config() -> crate::chain_spec::ChainSpec {
    crate::chain_spec::ChainSpec::from_genesis(
        "Testing",
        "test",
        ChainType::Development,
        || {
            integration_tests_genesis_config(
                vec![
                    crate::chain_spec::authority_keys_from_seed("Alice"),
                    crate::chain_spec::authority_keys_from_seed("Bob"),
                ],
                vec![],
                crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Alice"),
            )
        },
        vec![],
        None,
        None,
        None,
        None,
        Default::default(),
    )
}

/// Helper function to create RuntimeGenesisConfig for testing
pub fn integration_tests_genesis_config(
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
                    crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                    (
                        (*crate::chain_spec::ALICE_TSS_ACCOUNT_ID).into(),
                        crate::chain_spec::tss_x25519_public_key::ALICE,
                        "127.0.0.1:3001".as_bytes().to_vec(),
                    ),
                ),
                (
                    crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    (
                        (*crate::chain_spec::BOB_TSS_ACCOUNT_ID).into(),
                        crate::chain_spec::tss_x25519_public_key::BOB,
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
                (
                    // Seed phrase: "lake carry still awful point mention bike category tornado plate brass lock"
                    crate::chain_spec::get_account_id_from_seed::<sr25519::Public>(
                        "Charlie//stash",
                    ),
                    (
                        hex!["14d223daeec68671f07298c66c9458980a48bb89fb8a85d5df31131acad8d611"]
                            .into(),
                        crate::chain_spec::tss_x25519_public_key::BOB, // TODO (Nando): Should be Charlie
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
                (
                    crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                    (
                        hex!["5212c5f562f4a43b89caadfeb9f5896dd4084700afa72aa55ca306d689523f3a"]
                            .into(),
                        crate::chain_spec::tss_x25519_public_key::BOB, // TODO (Nando): Should be Dave
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
            ],
            signing_groups: vec![
                (
                    0,
                    vec![
                        crate::chain_spec::get_account_id_from_seed::<sr25519::Public>(
                            "Alice//stash",
                        ),
                        crate::chain_spec::get_account_id_from_seed::<sr25519::Public>(
                            "Charlie//stash",
                        ),
                    ],
                ),
                (
                    1,
                    vec![crate::chain_spec::get_account_id_from_seed::<sr25519::Public>(
                        "Bob//stash",
                    )],
                ),
            ],
            proactive_refresh_validators: vec![
                entropy_shared::ValidatorInfo {
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
                entropy_shared::ValidatorInfo {
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
                (crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Dave"), 0, None),
                (
                    crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Eve"),
                    1,
                    Some([
                        28, 63, 144, 84, 78, 147, 195, 214, 190, 234, 111, 101, 117, 133, 9, 198,
                        96, 96, 76, 140, 152, 251, 255, 28, 167, 38, 157, 185, 192, 42, 201, 82,
                    ]),
                ),
                (crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Ferdie"), 2, None),
            ],
        },
        vesting: Default::default(),
        transaction_storage: Default::default(),
        transaction_payment: Default::default(),
        nomination_pools: Default::default(),
    }
}
