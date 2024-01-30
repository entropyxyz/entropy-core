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

use crate::chain_spec::get_account_id_from_seed;
use crate::endowed_accounts::endowed_accounts_dev;

use entropy_runtime::{
    constants::currency::*, wasm_binary_unwrap, AuthorityDiscoveryConfig, BabeConfig,
    BalancesConfig, CouncilConfig, DemocracyConfig, ElectionsConfig, GrandpaConfig, ImOnlineConfig,
    IndicesConfig, MaxNominations, RuntimeGenesisConfig, SessionConfig, StakerStatus,
    StakingConfig, StakingExtensionConfig, SudoConfig, SystemConfig, TechnicalCommitteeConfig,
};
use entropy_runtime::{AccountId, Balance};
use entropy_shared::X25519PublicKey as TssX25519PublicKey;
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
            // 5GC6HbDfosvHUuCDkr8nAG81LBFNMgToMRfnFpa7GFD4td7q
            hex!["b693281e3001566f5e4c395f2f9a3389e425cd349d17d897435235ffeca55a3a"].into(),
            // stash -> Sr25519
            // 5FbwUrncUnFpa7wQKrxexXpEGZzM7ivDHwJNFQUQmjY38Cco
            hex!["9c872b973d78eb5d440b65f34b1b035b9f9b6a0f1462a048b93958a17d933c46"].into(),
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
            // grandpa -> ed25519
            // 5E1buCEBSvt1fssmxjfF4ZD28Q7iAyVf6sVZpi8oDHyQLwSK
            hex!["561aadf25fe061ef0181777ea6e12f5f442073470b6c8f7c64d59db1f8693b75"]
                .unchecked_into(),
        ),
        (
            // 5GWBLjvgQucinSSf5WvEDVhLRkBMCwMFavmwirfomw4RPaMV
            hex!["c45e969c3d0ffb54a8543c62418473e702e705fa97225c319831ac3c8cb7a659"].into(),
            // 5He4vcqwSEoJSDMDBVmWE7n9HmGs81rMNzviGY6uzL8RWYPu
            hex!["f69f2fea697d7c9499efebc0295b2c85f11ca3405b9da6afb590b29ca94cfe2f"].into(),
            // 5CHzj2XgRDXzSHZWQtWVcoWsYprEtUiLzJFiKhXZZzKih1qk
            hex!["0a22f94dd19755ede64eb09562ad30370349027fc258a70ff596bf139115e47f"]
                .unchecked_into(),
            // 5CwEFpcmgxqp69H9LG2BWb8nkQSst59WZy7ihXum49Hc8wDK
            hex!["26889a5f3113a398450e0043be96cd61b2a5706b549a57f168ae482a2c152f74"]
                .unchecked_into(),
            // 5EqpxZBuooBFWWv8871fKYJR9h7F4DFCVgZ539gPUF8gkbKp
            hex!["7ae26a776162f3b851ccd1c7d59d1bbe17a811307c267f164831a6ef804a5437"]
                .unchecked_into(),
            // 5DNVknZup4smom1tGmo1G4QXkzY7EU4aMjcekGES9CtkRQLr
            hex!["39cde9e9d96ef78dac973ca27e15961a6e6228eb07572b808f42718bd9677baa"]
                .unchecked_into(),
        ),
        (
            // 5H4NWR22bsQ6XuvjVcAnP7isutFrEXrnQ7sXGBzRNSzrfcGt
            hex!["dcec0833a062f351d32df4644cd68a96ee70d3d98b85f31e81d50357920b7c63"].into(),
            // 5Cca9Cv3giBxcG934caj6Tk2NWqRXK2nKFQ7zQhLT1xSx82Z
            hex!["184de1e2f1d451fcf187041794f2fd54827c397e3c932673b49b7c4d91e77b22"].into(),
            // 5GNRmLL5iE2kwHU5aAKamZgB8Y2ZjN4hxf2BRGnbsE4VUGwG
            hex!["be752e4027a49766ccbaf48154f06aedd1fd9f1f5b0bb95c2364de2cf4df8901"]
                .unchecked_into(),
            // 5HNeUG6K22VLNnCStbHW6KRAg3z6ybMoDy1VYbk8V1xUiG9t
            hex!["eadc2f6319b1f666513812631e5ba365c6a5741302eb45a451089f1a26d97a00"]
                .unchecked_into(),
            // 5GGard7xFFyRGFH1jRUYZfKmWALgkUFrYgh21gBQVCUjKrGn
            hex!["ba004fdb6740987e88c43a0f3147b23b2f005509bd4fa0ef795dfe5e16581806"]
                .unchecked_into(),
            // 5ELT9DsaGzwgZpMYsshQojhixkKDaG12CKtGbSc1kYTazrQQ
            hex!["647adc12dcd07d13e831b1378d25b5881ce33bc0b0b148f02bb1e3502e328e7a"]
                .unchecked_into(),
        ),
        (
            // 5HLBgTCNugSig3oCpfogq3L7x1UDuAiZWpuSmzpHuiQr6RRo
            hex!["e8fb830439ac929cadee5fed899defe6b574af2dbce4189dc50db5d7c14e6c4a"].into(),
            // 5GLPy6NDacLpKUdJ6U3bSiKFRGGrqLhpudwvaFFTnNXLpeE3
            hex!["bce8a3c75b84d1ab4020766d049c02cac37b2e42e6aa75b8577ea99e03e4b208"].into(),
            // 5EEuKvYG9cwTPTLHnrACGGBKXQKvyDLHnuVyW7cQU2Mdif6a
            hex!["603f8839abf317dc0054efdfc392a1087a25f8c45e0970c5fd772cf5100e4333"]
                .unchecked_into(),
            // 5FhJeoatmY44TPP4oFyykS68cp92owtQW61yQ2itMUXC5brA
            hex!["a09eaab2e4c3da616a2e746dc7a1ac4b38bfb7b2ec52231ebea1086ec0e2167a"]
                .unchecked_into(),
            // 5EX1CwbxF8BWq16FW1PYz9PM24Z41TSD1gVWzrxwWWoKp3y6
            hex!["6c87404dcac860f6b673f8e1b2c099ed13286be8508063413fa6ffb4d5af361c"]
                .unchecked_into(),
            // 5G5mruyipeqWb3cnsL1nfEdaYToK8nvGcq9Cm2xweRJzMBzs
            hex!["b1c1a89e34bdbf0bc2bae462c92e43d97c97e686fbf18b581c94c28a67b5bcb3"]
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
    crate::chain_spec::ChainSpec::from_genesis(
        "Entropy Testnet Local",
        "entropy_testnet_local",
        ChainType::Live,
        || {
            testnet_genesis_config(
                testnet_local_initial_authorities(),
                vec![],
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                testnet_local_initial_tss_servers(),
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

/// In practice it's a little hard for us to fill this out with correct information since we need
/// to spin up all the TSS servers we want at genesis and grab the keys and IPs to then put in
/// here.
///
/// Placeholders have been left here instead for illustrative purposes.
pub fn testnet_initial_tss_servers() -> Vec<(TssAccountId, TssX25519PublicKey, TssEndpoint)> {
    use std::str::FromStr;

    let node_1a = (
        TssAccountId::from_str("5EC2p79LfGKWEgY6YDGRzqSVwqFWnd2kndY1ABWTbAtp2zFC")
            .expect("Address should be valid."),
        [
            100, 151, 169, 160, 23, 148, 150, 198, 79, 84, 246, 123, 121, 218, 218, 81, 244, 106,
            253, 36, 65, 194, 62, 152, 230, 184, 70, 119, 249, 202, 181, 58,
        ],
        "0.0.0.0:3001".to_string(),
    );

    let node_1b = (
        TssAccountId::from_str("5DZnLJfveAjRiYU6UMYie3bNTLzowLu3YrwJkaMu94VMFX47")
            .expect("Address should be valid."),
        [
            85, 148, 71, 92, 127, 93, 61, 77, 253, 118, 162, 20, 84, 184, 191, 43, 176, 250, 245,
            53, 185, 9, 230, 7, 167, 77, 232, 240, 108, 58, 127, 8,
        ],
        "0.0.0.0:3001".to_string(),
    );

    let node_1c = (
        TssAccountId::from_str("5Fmnt2chPDfE6eUY4djfb9V9aFbbGPhdQ8UmeJbxLn42oR9a")
            .expect("Address should be valid."),
        [
            230, 255, 3, 85, 202, 18, 119, 146, 239, 9, 229, 2, 244, 250, 239, 16, 90, 182, 192,
            237, 190, 193, 222, 203, 183, 168, 6, 184, 30, 97, 115, 121,
        ],
        "0.0.0.0:3001".to_string(),
    );

    let node_2a = (
        TssAccountId::from_str("5CLgNaBBW2hFEgUkWnB2eYQik2HkeLDAA5oMfCrR75B9kdWy")
            .expect("Address should be valid."),
        [
            154, 171, 43, 100, 141, 250, 83, 95, 55, 165, 22, 243, 64, 187, 132, 7, 143, 199, 236,
            253, 85, 134, 94, 244, 15, 147, 193, 144, 12, 69, 134, 62,
        ],
        "0.0.0.0:3001".to_string(),
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
    crate::chain_spec::ChainSpec::from_genesis(
        "Entropy Testnet",
        "entropy_testnet",
        ChainType::Live,
        || {
            testnet_genesis_config(
                testnet_initial_authorities(),
                vec![],
                hex!["b848e84ef81dfeabef80caed10d7d34cc10e98e71fd00c5777b81177a510d871"].into(),
                testnet_initial_tss_servers(),
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
) -> RuntimeGenesisConfig {
    assert!(
        initial_authorities.len() == initial_tss_servers.len(),
        "Each validator node needs to have an accompanying threshold server."
    );

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
    const SIGNING_GROUPS: usize = 2;

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
                        // Note: We use the stash address here twice intentionally. Not sure why
                        // though...
                        x.1.clone(),
                        x.1.clone(),
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
            // For our initial testnet deployment we make it so that the validator stash accounts
            // cannot get slashed.
            //
            // We'll remove this in later stages of testing.
            invulnerables: initial_authorities.iter().map(|x| x.1.clone()).collect::<Vec<_>>(),
            slash_reward_fraction: Perbill::from_percent(10),
            stakers,
            ..Default::default()
        },
        staking_extension: StakingExtensionConfig {
            threshold_servers: initial_authorities
                .iter()
                .zip(initial_tss_servers.iter())
                .map(|(auth, tss)| {
                    (auth.1.clone(), (tss.0.clone(), tss.1, tss.2.as_bytes().to_vec()))
                })
                .collect::<Vec<_>>(),
            // We place all Stash accounts into the specified number of signing groups
            signing_groups: initial_authorities
                .iter()
                .map(|x| x.1.clone())
                .collect::<Vec<_>>()
                .as_slice()
                .chunks((initial_authorities.len() + SIGNING_GROUPS - 1) / SIGNING_GROUPS)
                .enumerate()
                .map(|(i, v)| (i as u8, v.to_vec()))
                .collect::<Vec<_>>(),
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
        relayer: Default::default(),
        vesting: Default::default(),
        transaction_storage: Default::default(),
        transaction_payment: Default::default(),
        nomination_pools: Default::default(),
    }
}
