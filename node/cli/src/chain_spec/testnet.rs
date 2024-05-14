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
use crate::endowed_accounts::endowed_testnet_accounts;

use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AuthorityDiscoveryConfig, BabeConfig,
    BalancesConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig, IndicesConfig, MaxNominations,
    ParametersConfig, ProgramsConfig, SessionConfig, StakerStatus, StakingConfig,
    StakingExtensionConfig, SudoConfig, TechnicalCommitteeConfig,
};
use entropy_runtime::{AccountId, Balance};
use entropy_shared::{
    X25519PublicKey as TssX25519PublicKey, DEVICE_KEY_AUX_DATA_TYPE, DEVICE_KEY_CONFIG_TYPE,
    DEVICE_KEY_HASH, DEVICE_KEY_PROXY, INITIAL_MAX_INSTRUCTIONS_PER_PROGRAM,
};
use grandpa_primitives::AuthorityId as GrandpaId;
use hex_literal::hex;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sc_service::ChainType;
use sc_telemetry::TelemetryEndpoints;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{crypto::UncheckedInto, sr25519};
use sp_runtime::Perbill;

/// The AccountID of a Threshold Signature server. This is to meant to be registered on-chain.
type TssAccountId = sp_runtime::AccountId32;

/// The endpoint at which to reach a Threshold Signature server.
///
/// The format should be in the form of `scheme://hostname:port`.
type TssEndpoint = String;

pub fn testnet_local_initial_authorities(
) -> Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> {
    vec![
        crate::chain_spec::authority_keys_from_seed("Alice"),
        crate::chain_spec::authority_keys_from_seed("Bob"),
    ]
}

/// Generates the keys for the initial testnet authorities.
///
/// These public keys were generated using the `generate-validator-node-keys.sh` script which can
/// be found in this repository.
///
/// The format of the derivation paths is as follows: `$secretPhrase//$keyType`, where `keyType`
/// can be one of: `stash`, `controller`, `gran`, `babe`, `imon`, or `audi`.
///
/// Note that the latter four keys are what are known as "session keys", and their exact type and
/// number is configurable in the runtime.
pub fn testnet_initial_authorities(
) -> Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> {
    vec![
        (
            // stash -> Sr25519
            // 5FbwUrncUnFpa7wQKrxexXpEGZzM7ivDHwJNFQUQmjY38Cco
            hex!["9c872b973d78eb5d440b65f34b1b035b9f9b6a0f1462a048b93958a17d933c46"].into(),
            // controller -> Sr25519
            // 5GC6HbDfosvHUuCDkr8nAG81LBFNMgToMRfnFpa7GFD4td7q
            hex!["b693281e3001566f5e4c395f2f9a3389e425cd349d17d897435235ffeca55a3a"].into(),
            // grandpa -> Ed25519
            // 5E1buCEBSvt1fssmxjfF4ZD28Q7iAyVf6sVZpi8oDHyQLwSK
            hex!["561aadf25fe061ef0181777ea6e12f5f442073470b6c8f7c64d59db1f8693b75"]
                .unchecked_into(),
            // babe -> Sr25519
            // 5F6kuqyMq38QPJhMjfUsoF5o8EjSkdPXKdQeAiAqEdGgFQdY
            hex!["86457973f03814d240c0818857229acadd1b517d848b6e826028c5279cd2bb1e"]
                .unchecked_into(),
            // im online -> Sr25519
            // 5GbrYiuSkFAKh2BE5WR8in76WRFWpN2oZ9tGzfJ9TZqSLnvd
            hex!["c8b2cbe76eaede0dd05ef3f7ae68c3c61458ddd5d93e816515aa2bdfb7802256"]
                .unchecked_into(),
            // authority discovery -> Sr25519
            // 5H4KA7kqNxEQUStzDmjC1w1311ZGaTC1RE2m7riQa4j8FAND
            hex!["dce0c14c4f48c018d9d8c55135b8cb2e4312256beabd75bd0a45c0b56bf7b12f"]
                .unchecked_into(),
        ),
        (
            // 5He4vcqwSEoJSDMDBVmWE7n9HmGs81rMNzviGY6uzL8RWYPu
            hex!["f69f2fea697d7c9499efebc0295b2c85f11ca3405b9da6afb590b29ca94cfe2f"].into(),
            // 5GWBLjvgQucinSSf5WvEDVhLRkBMCwMFavmwirfomw4RPaMV
            hex!["c45e969c3d0ffb54a8543c62418473e702e705fa97225c319831ac3c8cb7a659"].into(),
            // 5DNVknZup4smom1tGmo1G4QXkzY7EU4aMjcekGES9CtkRQLr
            hex!["39cde9e9d96ef78dac973ca27e15961a6e6228eb07572b808f42718bd9677baa"]
                .unchecked_into(),
            // 5CHzj2XgRDXzSHZWQtWVcoWsYprEtUiLzJFiKhXZZzKih1qk
            hex!["0a22f94dd19755ede64eb09562ad30370349027fc258a70ff596bf139115e47f"]
                .unchecked_into(),
            // 5CwEFpcmgxqp69H9LG2BWb8nkQSst59WZy7ihXum49Hc8wDK
            hex!["26889a5f3113a398450e0043be96cd61b2a5706b549a57f168ae482a2c152f74"]
                .unchecked_into(),
            // 5EqpxZBuooBFWWv8871fKYJR9h7F4DFCVgZ539gPUF8gkbKp
            hex!["7ae26a776162f3b851ccd1c7d59d1bbe17a811307c267f164831a6ef804a5437"]
                .unchecked_into(),
        ),
        (
            // 5Cca9Cv3giBxcG934caj6Tk2NWqRXK2nKFQ7zQhLT1xSx82Z
            hex!["184de1e2f1d451fcf187041794f2fd54827c397e3c932673b49b7c4d91e77b22"].into(),
            // 5H4NWR22bsQ6XuvjVcAnP7isutFrEXrnQ7sXGBzRNSzrfcGt
            hex!["dcec0833a062f351d32df4644cd68a96ee70d3d98b85f31e81d50357920b7c63"].into(),
            // 5ELT9DsaGzwgZpMYsshQojhixkKDaG12CKtGbSc1kYTazrQQ
            hex!["647adc12dcd07d13e831b1378d25b5881ce33bc0b0b148f02bb1e3502e328e7a"]
                .unchecked_into(),
            // 5GNRmLL5iE2kwHU5aAKamZgB8Y2ZjN4hxf2BRGnbsE4VUGwG
            hex!["be752e4027a49766ccbaf48154f06aedd1fd9f1f5b0bb95c2364de2cf4df8901"]
                .unchecked_into(),
            // 5HNeUG6K22VLNnCStbHW6KRAg3z6ybMoDy1VYbk8V1xUiG9t
            hex!["eadc2f6319b1f666513812631e5ba365c6a5741302eb45a451089f1a26d97a00"]
                .unchecked_into(),
            // 5GGard7xFFyRGFH1jRUYZfKmWALgkUFrYgh21gBQVCUjKrGn
            hex!["ba004fdb6740987e88c43a0f3147b23b2f005509bd4fa0ef795dfe5e16581806"]
                .unchecked_into(),
        ),
        (
            // 5GLPy6NDacLpKUdJ6U3bSiKFRGGrqLhpudwvaFFTnNXLpeE3
            hex!["bce8a3c75b84d1ab4020766d049c02cac37b2e42e6aa75b8577ea99e03e4b208"].into(),
            // 5HLBgTCNugSig3oCpfogq3L7x1UDuAiZWpuSmzpHuiQr6RRo
            hex!["e8fb830439ac929cadee5fed899defe6b574af2dbce4189dc50db5d7c14e6c4a"].into(),
            // 5G5mruyipeqWb3cnsL1nfEdaYToK8nvGcq9Cm2xweRJzMBzs
            hex!["b1c1a89e34bdbf0bc2bae462c92e43d97c97e686fbf18b581c94c28a67b5bcb3"]
                .unchecked_into(),
            // 5EEuKvYG9cwTPTLHnrACGGBKXQKvyDLHnuVyW7cQU2Mdif6a
            hex!["603f8839abf317dc0054efdfc392a1087a25f8c45e0970c5fd772cf5100e4333"]
                .unchecked_into(),
            // 5FhJeoatmY44TPP4oFyykS68cp92owtQW61yQ2itMUXC5brA
            hex!["a09eaab2e4c3da616a2e746dc7a1ac4b38bfb7b2ec52231ebea1086ec0e2167a"]
                .unchecked_into(),
            // 5EX1CwbxF8BWq16FW1PYz9PM24Z41TSD1gVWzrxwWWoKp3y6
            hex!["6c87404dcac860f6b673f8e1b2c099ed13286be8508063413fa6ffb4d5af361c"]
                .unchecked_into(),
        ),
    ]
}

/// The configuration used for a local testnet network spun up using the `docker-compose` setup
/// provided in this repository.
///
/// This configuration matches the same setup as the `testnet`, with the exception that is uses
/// two well-known accounts (Alice and Bob) as the authorities.
pub fn testnet_local_config() -> crate::chain_spec::ChainSpec {
    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("Entropy Testnet Local")
        .with_id("entropy_testnet_local")
        .with_chain_type(ChainType::Live)
        .with_genesis_config_patch(testnet_genesis_config(
            testnet_local_initial_authorities(),
            vec![],
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            testnet_local_initial_tss_servers(),
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

pub fn testnet_local_initial_tss_servers() -> Vec<(TssAccountId, TssX25519PublicKey, TssEndpoint)> {
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

/// Information about the initial set of Threshold Signature Signing servers.
///
/// In practice it's a little annoying for us to fill this out with correct information since we
/// need to spin up all the TSS servers we want at genesis and grab the keys and IPs to then put in
/// here.
///
/// However, this can be done by:
/// - First, spinning up the machines you expect to be running at genesis
/// - Then, running each TSS server with the `--setup-only` flag to get the `TssAccountId` and
/// `TssX25519PublicKey`
/// - Finally, writing all that information back here, and generating the chainspec from that.
///
/// Note that if the KVDB of the TSS is deleted at any point during this process you will end up
/// with different `AccountID`s and `PublicKey`s.
pub fn testnet_initial_tss_servers() -> Vec<(TssAccountId, TssX25519PublicKey, TssEndpoint)> {
    use std::str::FromStr;

    let node_1a = (
        TssAccountId::from_str("5EjwRRgCiHd7aaPzFjNGma9FN3kvvgQT6e5VNroptUGFGxBu")
            .expect("Address should be valid."),
        [
            82, 228, 47, 129, 124, 56, 118, 161, 246, 72, 156, 57, 62, 188, 129, 124, 13, 238, 54,
            198, 84, 61, 178, 36, 191, 56, 41, 39, 173, 70, 9, 67,
        ],
        "100.26.207.49:3001".to_string(),
    );

    let node_1b = (
        TssAccountId::from_str("5GipHsBvjCbJgg5EZMUnMix8nzEr2GezFYdGJEmqCZ23hqtb")
            .expect("Address should be valid."),
        [
            121, 253, 31, 146, 191, 150, 181, 175, 110, 217, 172, 227, 186, 191, 133, 80, 95, 135,
            10, 107, 31, 67, 10, 98, 215, 34, 26, 10, 188, 59, 71, 100,
        ],
        "34.200.237.166:3001".to_string(),
    );

    let node_1c = (
        TssAccountId::from_str("5FexGJegpjWcEGP3UQyabUsfQEs48tCFMzKjhhtaVsbinCJM")
            .expect("Address should be valid."),
        [
            245, 229, 104, 210, 55, 224, 110, 176, 133, 186, 130, 253, 2, 112, 205, 166, 94, 104,
            36, 157, 25, 170, 72, 247, 152, 130, 139, 244, 4, 67, 162, 0,
        ],
        "184.72.189.154:3001".to_string(),
    );

    let node_2a = (
        TssAccountId::from_str("5FX122MC2ChptKi9setzqjtPYX5krarK9bsY8SkXddaX2Ub8")
            .expect("Address should be valid."),
        [
            164, 83, 190, 36, 18, 54, 59, 116, 203, 177, 95, 170, 9, 187, 102, 128, 189, 5, 41,
            196, 3, 154, 37, 23, 133, 28, 168, 221, 37, 204, 186, 61,
        ],
        "184.73.19.95:3001".to_string(),
    );

    vec![node_1a, node_1b, node_1c, node_2a]
}

/// The testnet configuration uses four validator nodes with private keys controlled by the deployer
/// of the network (so Entropy in this case).
///
/// If you want to run your own version you can either:
///  - Update all the accounts here using keys you control, or
///  - Run the `testnet-local` config, which uses well-known keys
pub fn testnet_config() -> crate::chain_spec::ChainSpec {
    ChainSpec::builder(wasm_binary_unwrap(), Default::default())
        .with_name("Entropy Testnet")
        .with_id("entropy_testnet")
        .with_chain_type(ChainType::Live)
        .with_genesis_config_patch(testnet_genesis_config(
            testnet_initial_authorities(),
            vec![],
            hex!["b848e84ef81dfeabef80caed10d7d34cc10e98e71fd00c5777b81177a510d871"].into(),
            testnet_initial_tss_servers(),
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
    initial_tss_servers: Vec<(TssAccountId, TssX25519PublicKey, TssEndpoint)>,
) -> serde_json::Value {
    assert!(
        initial_authorities.len() == initial_tss_servers.len(),
        "Each validator node needs to have an accompanying threshold server."
    );

    // Note that any endowed_accounts added here will be included in the `elections` and
    // `technical_committee` genesis configs. If you don't want that, don't push those accounts to
    // this list.
    let mut endowed_accounts = vec![];

    // Ensure that the `testnet-local` config doesn't have a duplicate balance since `Alice` is
    // both a validator and root.
    if !endowed_accounts.contains(&root_key) {
        endowed_accounts.push(root_key.clone());
    }

    // We endow the:
    // - Initial TSS server accounts
    // - Initial the validator stash accounts
    // - Initial nominator accounts
    initial_tss_servers
        .iter()
        .map(|tss| &tss.0)
        .chain(initial_authorities.iter().map(|x| &x.0))
        .chain(initial_nominators.iter())
        .for_each(|x| {
            if !endowed_accounts.contains(x) {
                endowed_accounts.push(x.clone())
            }
        });

    // stakers: all validators and nominators.
    //
    // The validators assigned here must match those in the Session genesis config.
    let mut rng = rand::thread_rng();
    let stakers = initial_authorities
        .iter()
        .map(|x| {
            (
                x.0.clone(), // Stash account
                x.1.clone(), // Controller account, unused
                STASH,
                StakerStatus::Validator,
            )
        })
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
    const SIGNING_GROUPS: usize = 2;

    serde_json::json!( {
        "balances": BalancesConfig {
            balances: endowed_accounts
                        .iter()
                        .chain(endowed_testnet_accounts().iter())
                        .cloned()
                        .map(|x| (x, ENDOWMENT))
                        .collect(),
        },
        "indices": IndicesConfig { indices: vec![] },
        "session": SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        // The `ValidatorId` used here must match the `stakers` from the Staking
                        // genesis config.
                        //
                        // Note: We use the stash address here twice intentionally. Not sure why
                        // though...
                        x.0.clone(), // This is the `T::AccountId`
                        x.0.clone(), // This is the `T::ValidatorId`
                        // The exact number and type of session keys are configured as a runtime
                        // parameter
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
            // For our initial testnet deployment we make it so that the validator stash accounts
            // cannot get slashed.
            //
            // We'll remove this in later stages of testing.
            invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
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
                .take((num_endowed_accounts + 1) / 3)
                .cloned()
                .map(|member| (member, STASH))
                .collect(),
        },
        "technicalCommittee": TechnicalCommitteeConfig {
            members: endowed_accounts
                .iter()
                .take((num_endowed_accounts + 1) / 3)
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
        "grandpa": GrandpaConfig { authorities: vec![], ..Default::default() },
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
