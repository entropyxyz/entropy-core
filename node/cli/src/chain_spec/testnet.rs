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

use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AuthorityDiscoveryConfig, BabeConfig,
    BalancesConfig, CouncilConfig, DemocracyConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig,
    IndicesConfig, MaxNominations, RelayerConfig, RuntimeGenesisConfig, SessionConfig,
    StakerStatus, StakingConfig, StakingExtensionConfig, SudoConfig, SystemConfig,
    TechnicalCommitteeConfig,
};
use grandpa_primitives::AuthorityId as GrandpaId;
use hex_literal::hex;
use node_primitives::{AccountId, Balance};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::ChainType;
use sc_telemetry::TelemetryEndpoints;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{crypto::UncheckedInto, sr25519};
use sp_runtime::Perbill;

pub fn testnet_local_initial_authorities(
) -> Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> {
    vec![
        crate::chain_spec::authority_keys_from_seed("Alice"),
        crate::chain_spec::authority_keys_from_seed("Bob"),
    ]
}

pub fn testnet_initial_authorities(
) -> Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> {
    // stash, controller, session-key
    // generated with secret:
    // for i in 1 2 3 4 ; do for j in stash controller; do subkey inspect "$secret"/fir/$j/$i; done; done
    //
    // and
    //
    // for i in 1 2 3 4 ; do for j in session; do subkey --ed25519 inspect "$secret"//fir//$j//$i; done; done
    vec![
        (
            // controller -> Sr25519
            // 5DUp9KHrDi8k8R4e2rPZhbxudUzEuNtxwUvfbCYtCZRA4no6
            hex!["3e9f4983e0cd02803c0d2e0fd58ea8d89e0a279e829a1aa9fdc1162a1a53e359"].into(),
            // stash -> Sr25519
            // 5FNHcKqJzVGfSCFNAsw3YfPdHioKN7Usdtd32vBEkU1LjVV7
            hex!["921d7e7421fa0120839c5f4f29b651421720d79e3885856abb127ed8d5744d22"].into(),
            // grandpa -> ed25519
            // 5H9kQJyK9THVhvgcKBSGWGidjSezNTdUn5p5Jc2c75kV6Txk
            hex!["e105f69f91ddfa8499434c6cf03f0208ee26bf57446f70558ef6bc5bfbdcd258"]
                .unchecked_into(),
            // babe -> Sr25519
            // 5D7MndGJ3BVvm7sAcuVuXffVuDfTrSjS4cSieVJcQeqLfycR
            hex!["2e4268b609fac59c448d755d3b63ef30d897c6f7e0eeb3eeff3e7d0e0d93cc12"]
                .unchecked_into(),
            // im online -> Sr25519
            // 5F4RQ5dTKKyvmkuVuKTTUUqDFm9oRe8gZRpmU8fhDtpxH4ar
            hex!["847d4be0524b7eac945860cfd1bcd8d40e6cfcfbc7634251ddcdb89c54d4356d"]
                .unchecked_into(),
            // authority discovery -> Sr25519
            // 5FBo1QLcDGzH9zZcpE59dFJjWnqqpXnT6ZcwF6y2fGByGNKf
            hex!["8a1cc1b2c4cd82693fc73714a4ef9937c1a413f612e0f46e095b3cf60f928f73"]
                .unchecked_into(),
        ),
        (
            // 5Gen3ZR6zY4bo55KwioD6bE57GVv8QnBEzL7b5t9rFUZXGE2
            hex!["caed5ff7554fd17349372086115af48ffa4329ad92eb33b62f8ef3de425f4c42"].into(),
            // 5CY72U7tqHNGspa2jE9MpJomDtBnzNSC73yq3dB8tsGohH3F
            hex!["14e59e9d3c8b718545a9fc6994a83eb49f801c38d7cc268ad05dbe281cd5ed63"].into(),
            // 5EkndhZ94fKCnx2zQ2o88rjGGupzhiKraHkEuxhwvDtQDzi5
            hex!["770a5ca4319c336b603afc1561529bb9be2ef91a1d54ab3cc1f3b86ee89525c9"]
                .unchecked_into(),
            // 5FZJsJ3zojt8fqiiR1LE1YtwmGfuVHicLrfBWfQ5ioH5hAsd
            hex!["9a856db37bedb9376c143bf6b033737205a7f04c7e13102fdd902d94d9130c56"]
                .unchecked_into(),
            // 5CDmK3XPvYij5UBeCWXQwrfkboKmAHL3YLfZZeUf2AHHmXsv
            hex!["06e8d69f5e46f672f07ab84387dd81cf7f592ada2153aaab7f1be723bf37bb3b"]
                .unchecked_into(),
            // 5CXJMPeb9xXHgRQYRj9kV3UpvacAc2qNEydrZH9WjyD191kp
            hex!["1448807387ae3a70de2c86ce09a00f7f856344459413027520f48414f6cff972"]
                .unchecked_into(),
        ),
        (
            // 5DwWZzE82vNXbLdo8hpnjxrwVSmhBRjVZczQBcyH3Z2oRWKX
            hex!["52fbc068cc0917950befb99cc3f9077d4a2fb0bdaefeaf19a49a88481a11b412"].into(),
            // 5CD3xHo9rp1gGNnnpVgRtVTN55bRHKbaYbDDSr32T9usNLsE
            hex!["065d9d92615eb51aca8d14b06a84d7bf6700f0914095f9c4a8b0e0b62160ea42"].into(),
            // 5FdoJSe3oGSDFU8ebnmQpKr4FUeM9tgtsRMaNWYbT42AzVLV
            hex!["9df22049a7c64c3728f798ec667949930c6835d8f63ef3d47322096ab5e341a1"]
                .unchecked_into(),
            // 5DJ2e2NVmZe2H81MFp3zLQSy1CQmHTmpidB8GCSo3gow2oeh
            hex!["3665a6484210be60c355d1521644c87348f9a0c0c8621d3ea58de3a907508417"]
                .unchecked_into(),
            // 5EFsfWeGvDLmdv6oKmkK9FtieSuTTFzQg8p4bZqxwC5k8q5n
            hex!["60fd2e8b6823646393021617820571411e09260b059203743182d565235aef03"]
                .unchecked_into(),
            // 5EeXANUui1gHckcw7zF3AdmwXyFBzRcicC5wU36CY4cHdNGF
            hex!["7242cf0d47e22380f5d16e4d283cd2fc33d1d7526cb4fbbf9787b564f1ce9679"]
                .unchecked_into(),
        ),
        (
            // 5FLc2mJXwzfPsWAtaLAK9f1RUirr3hBRP9btADeYrSY6TSkn
            hex!["90d503d66e6f555429433573bf0998f60e4916b3e80f16fed334f11470533d4b"].into(),
            // 5CXuG9z2XcHwdqTAG451tNvcr9PSrVfEXtCkzkRwPnFLBE7Y
            hex!["14be04b5670df7ca712ce3e67d620fd0846f87fa34de72bb2f80c9f0c881b401"].into(),
            // 5DZ4Sq7C6fDPRgm4im5H6wyhL3SbUqCWAfRB9gMc1hFAgHrb
            hex!["41dc69dafec1016f5d4168975a6c7615017703f6d8b5fdeeca4952ed91fabf67"]
                .unchecked_into(),
            // 5FWy2dvHo4B2CnkwumMQgM5hVUV3mgviB16WQ1DWqFcZM8bi
            hex!["98bc276917d57ead1874841aa956f9fa28a8c9a21a3f03eb982186fead6a2467"]
                .unchecked_into(),
            // 5FvBb7ZaSny6h8G9HCdKEZH79o7BfjVxKjsfMNc7vgoMFZ3f
            hex!["aa71142ae23a5c60f33a064462c44c5425c48c7345f12dc9ad00a56580e8835b"]
                .unchecked_into(),
            // 5ELz6TfwTwbwAsXoEycB5oTQCcMPLipEqDRsjVw7GYot2pNh
            hex!["64e30dfddf0e622b1db1e6ad27f3724b349ed9369862b84ec9a1a262c724603e"]
                .unchecked_into(),
        ),
    ]
}

pub fn testnet_local_config() -> crate::chain_spec::ChainSpec {
    crate::chain_spec::ChainSpec::from_genesis(
        "EntropyTestnetLocal",
        "ETestLocal",
        ChainType::Live,
        || {
            testnet_genesis_config(
                testnet_local_initial_authorities(),
                vec![],
                crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Alice"),
            )
        },
        vec![],
        Some(
            TelemetryEndpoints::new(vec![(
                crate::chain_spec::STAGING_TELEMETRY_URL.to_string(),
                0,
            )])
            .expect("Staging telemetry url is valid; qed"),
        ),
        Some(crate::chain_spec::DEFAULT_PROTOCOL_ID),
        None,
        Some(crate::chain_spec::entropy_properties()),
        Default::default(),
    )
}

/// Development config (single validator Alice)
pub fn testnet_config() -> crate::chain_spec::ChainSpec {
    crate::chain_spec::ChainSpec::from_genesis(
        "EntropyTestnet",
        "ETest",
        ChainType::Live,
        || {
            testnet_genesis_config(
                testnet_initial_authorities(),
                vec![],
                hex!["6a16ded05ff7a50716e1ca943f0467c60b4b71c2a7fd7f75b6333b8af80b6e6f"].into(),
            )
        },
        vec![],
        Some(
            TelemetryEndpoints::new(vec![(
                crate::chain_spec::STAGING_TELEMETRY_URL.to_string(),
                0,
            )])
            .expect("Staging telemetry url is valid; qed"),
        ),
        Some(crate::chain_spec::DEFAULT_PROTOCOL_ID),
        None,
        Some(crate::chain_spec::entropy_properties()),
        Default::default(),
    )
}

/// Helper function to create RuntimeGenesisConfig for testing
pub fn testnet_genesis_config(
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
                        crate::chain_spec::tss_account_id::ALICE.clone(),
                        crate::chain_spec::tss_x25519_public_key::ALICE,
                        "127.0.0.1:3001".as_bytes().to_vec(),
                    ),
                ),
                (
                    crate::chain_spec::get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                    (
                        crate::chain_spec::tss_account_id::BOB.clone(),
                        crate::chain_spec::tss_x25519_public_key::BOB,
                        "127.0.0.1:3002".as_bytes().to_vec(),
                    ),
                ),
            ],
            signing_groups: vec![
                (
                    0,
                    vec![crate::chain_spec::get_account_id_from_seed::<sr25519::Public>(
                        "Alice//stash",
                    )],
                ),
                (
                    1,
                    vec![crate::chain_spec::get_account_id_from_seed::<sr25519::Public>(
                        "Bob//stash",
                    )],
                ),
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
