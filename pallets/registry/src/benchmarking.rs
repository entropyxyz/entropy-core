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

//! Benchmarking setup for pallet-propgation
use codec::Encode;
use entropy_shared::{ValidatorInfo, MAX_SIGNERS};
use frame_benchmarking::v2::*;
use frame_support::{
    traits::{Currency, Get},
    BoundedVec,
};
use frame_system::{EventRecord, RawOrigin};
use pallet_programs::{OraclePointers, ProgramInfo, Programs};
use pallet_session::Validators;
use pallet_staking_extension::{
    benchmarking::create_validators, JumpStartDetails, JumpStartProgress, JumpStartStatus,
    ServerInfo, ThresholdServers, ThresholdToStash,
};
use sp_runtime::traits::Hash;
use sp_std::{vec, vec::Vec};

use super::*;
#[allow(unused)]
use crate::Pallet as Registry;

const SEED: u32 = 0;
const NULL_ARR: [u8; 32] = [0; 32];

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

pub fn add_validators<T: Config>(
    validator_amount: u32,
) -> Vec<<T as pallet_session::Config>::ValidatorId> {
    let validators = create_validators::<T>(validator_amount, SEED);
    let account = account::<T::AccountId>("ts_account", 1, SEED);
    let server_info = ServerInfo {
        tss_account: account,
        x25519_public_key: NULL_ARR,
        endpoint: vec![20],
        tdx_quote: Vec::new(),
    };
    for validator in &validators {
        <ThresholdServers<T>>::insert(validator, server_info.clone());
    }
    validators
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn jump_start_network() {
        let sig_req_account: T::AccountId = whitelisted_caller();
        let balance =
            <T as pallet_staking_extension::Config>::Currency::minimum_balance() * 100u32.into();
        let _ = <T as pallet_staking_extension::Config>::Currency::make_free_balance_be(
            &sig_req_account,
            balance,
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(sig_req_account.clone()));

        assert_last_event::<T>(Event::StartedNetworkJumpStart().into());
    }

    #[benchmark]
    fn confirm_jump_start_done(c: Linear<0, { MAX_SIGNERS as u32 }>) {
        let expected_verifying_key = BoundedVec::default();

        let mut accounts = vec![];
        for i in 0..MAX_SIGNERS {
            accounts.push(account::<T::AccountId>("ts_account", i as u32, SEED));
        }

        let validators = add_validators::<T>(MAX_SIGNERS as u32);
        <Validators<T>>::set(validators.clone());

        for i in 0..MAX_SIGNERS {
            <ThresholdToStash<T>>::insert(accounts[i as usize].clone(), &validators[i as usize]);
        }

        <JumpStartProgress<T>>::put(JumpStartDetails {
            jump_start_status: JumpStartStatus::InProgress(0),
            confirmations: vec![validators[0].clone(), validators[0].clone()],
            verifying_key: None,
            parent_key_threshold: 2,
        });

        // Add the jump start record
        let block_number = <frame_system::Pallet<T>>::block_number();
        let initial_signers = accounts
            .iter()
            .map(|account_id| ValidatorInfo {
                x25519_public_key: [0; 32],
                ip_address: vec![20],
                tss_account: account_id.encode(),
            })
            .collect();
        <JumpstartDkg<T>>::set(block_number, initial_signers);

        let balance =
            <T as pallet_staking_extension::Config>::Currency::minimum_balance() * 100u32.into();
        let _ = <T as pallet_staking_extension::Config>::Currency::make_free_balance_be(
            &accounts[1],
            balance,
        );

        #[extrinsic_call]
        confirm_jump_start(RawOrigin::Signed(accounts[1].clone()), expected_verifying_key);

        assert_last_event::<T>(Event::<T>::FinishedNetworkJumpStart().into());
    }

    #[benchmark]
    fn confirm_jump_start_confirm(c: Linear<0, { MAX_SIGNERS as u32 }>) {
        let threshold_account: T::AccountId = whitelisted_caller();
        let expected_verifying_key = BoundedVec::default();

        // add validators
        for i in 0..MAX_SIGNERS {
            let validators = add_validators::<T>(MAX_SIGNERS as u32);
            <Validators<T>>::set(validators.clone());
            <ThresholdToStash<T>>::insert(&threshold_account, &validators[i as usize]);
        }

        // Add the jump start record
        let block_number = <frame_system::Pallet<T>>::block_number();
        let initial_signers = (0..MAX_SIGNERS)
            .map(|_| ValidatorInfo {
                x25519_public_key: [0; 32],
                ip_address: vec![20],
                tss_account: threshold_account.encode(),
            })
            .collect();
        <JumpstartDkg<T>>::set(block_number, initial_signers);

        <JumpStartProgress<T>>::put(JumpStartDetails {
            jump_start_status: JumpStartStatus::InProgress(0),
            confirmations: vec![],
            verifying_key: None,
            parent_key_threshold: 2,
        });

        let balance =
            <T as pallet_staking_extension::Config>::Currency::minimum_balance() * 100u32.into();
        let _ = <T as pallet_staking_extension::Config>::Currency::make_free_balance_be(
            &threshold_account,
            balance,
        );

        #[extrinsic_call]
        confirm_jump_start(RawOrigin::Signed(threshold_account.clone()), expected_verifying_key);

        let validator_stash =
            pallet_staking_extension::Pallet::<T>::threshold_to_stash(&threshold_account).unwrap();
        assert_last_event::<T>(Event::<T>::JumpStartConfirmation(validator_stash, 1).into());
    }

    #[benchmark]
    fn register(p: Linear<1, { T::MaxProgramHashes::get() }>) {
        let program_modification_account: T::AccountId = whitelisted_caller();
        let signature_request_account: T::AccountId = whitelisted_caller();

        let program = vec![0u8];
        let configuration_schema = vec![1u8];
        let auxiliary_data_schema = vec![2u8];
        let oracle_data_pointers: OraclePointers<T> =
            BoundedVec::try_from([vec![3u8]].to_vec()).unwrap();
        let program_hash = T::Hashing::hash(&program);
        let programs_info = BoundedVec::try_from(vec![
            ProgramInstance {
                program_pointer: program_hash,
                program_config: vec![],
            };
            p as usize
        ])
        .unwrap();

        Programs::<T>::insert(
            program_hash,
            ProgramInfo {
                bytecode: program,
                configuration_schema,
                auxiliary_data_schema,
                oracle_data_pointers,
                deployer: program_modification_account.clone(),
                ref_counter: 0,
                version_number: 0,
            },
        );

        let network_verifying_key = entropy_shared::DAVE_VERIFYING_KEY;
        <pallet_staking_extension::JumpStartProgress<T>>::put(JumpStartDetails {
            jump_start_status: JumpStartStatus::Done,
            confirmations: vec![],
            verifying_key: Some(BoundedVec::try_from(network_verifying_key.to_vec()).unwrap()),
            parent_key_threshold: 0,
        });

        let balance =
            <T as pallet_staking_extension::Config>::Currency::minimum_balance() * 100u32.into();
        let _ = <T as pallet_staking_extension::Config>::Currency::make_free_balance_be(
            &signature_request_account,
            balance,
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(signature_request_account.clone()),
            program_modification_account,
            programs_info,
        );

        use core::str::FromStr;
        use synedrion::DeriveChildKey;

        let network_verifying_key =
            k256::ecdsa::VerifyingKey::try_from(network_verifying_key.as_slice()).unwrap();

        // We subtract one from the count since this gets incremented after a succesful registration,
        // and we're interested in the account we just registered.
        let count = <Registered<T>>::count() - 1;
        let derivation_path =
            bip32::DerivationPath::from_str(&scale_info::prelude::format!("m/0/{}", count))
                .unwrap();

        let expected_verifying_key =
            network_verifying_key.derive_verifying_key_bip32(&derivation_path).unwrap();
        let expected_verifying_key =
            BoundedVec::try_from(expected_verifying_key.to_encoded_point(true).as_bytes().to_vec())
                .unwrap();

        assert_last_event::<T>(
            Event::<T>::AccountRegistered(
                signature_request_account,
                expected_verifying_key.clone(),
            )
            .into(),
        );

        assert!(Registered::<T>::contains_key(expected_verifying_key));
    }

    #[benchmark]
    fn change_program_instance(
        n: Linear<1, { T::MaxProgramHashes::get() }>,
        o: Linear<1, { T::MaxProgramHashes::get() }>,
    ) {
        let program_modification_account: T::AccountId = whitelisted_caller();
        let program = vec![0u8];
        let configuration_schema = vec![1u8];
        let auxiliary_data_schema = vec![2u8];
        let derivation_path = vec![3u8];
        let oracle_data_pointers: OraclePointers<T> =
            BoundedVec::try_from([vec![3u8]].to_vec()).unwrap();
        let program_hash = T::Hashing::hash(&program);
        let programs_info = BoundedVec::try_from(vec![
            ProgramInstance {
                program_pointer: program_hash,
                program_config: vec![],
            };
            o as usize
        ])
        .unwrap();
        let new_program = vec![1u8];
        let new_program_hash = T::Hashing::hash(&new_program);
        let new_programs_info = BoundedVec::try_from(vec![
            ProgramInstance {
                program_pointer: new_program_hash,
                program_config: vec![],
            };
            n as usize
        ])
        .unwrap();
        let sig_req_account: T::AccountId = whitelisted_caller();
        Programs::<T>::insert(
            program_hash,
            ProgramInfo {
                bytecode: program,
                configuration_schema: configuration_schema.clone(),
                auxiliary_data_schema: auxiliary_data_schema.clone(),
                oracle_data_pointers: oracle_data_pointers.clone(),
                deployer: program_modification_account.clone(),
                ref_counter: 0,
                version_number: 0,
            },
        );
        Programs::<T>::insert(
            new_program_hash,
            ProgramInfo {
                bytecode: new_program,
                configuration_schema,
                auxiliary_data_schema,
                oracle_data_pointers,
                deployer: program_modification_account.clone(),
                ref_counter: o as u128,
                version_number: 0,
            },
        );
        let balance =
            <T as pallet_staking_extension::Config>::Currency::minimum_balance() * 100u32.into();
        let _ = <T as pallet_staking_extension::Config>::Currency::make_free_balance_be(
            &sig_req_account,
            balance,
        );
        <Registered<T>>::insert(
            &BoundedVec::default(),
            RegisteredInfo {
                program_modification_account: sig_req_account.clone(),
                programs_data: programs_info,
                derivation_path,
                version_number: T::KeyVersionNumber::get(),
            },
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(sig_req_account.clone()),
            BoundedVec::default(),
            new_programs_info.clone(),
        );

        assert_last_event::<T>(
            Event::ProgramInfoChanged(sig_req_account.clone(), new_programs_info).into(),
        );
    }

    #[benchmark]
    fn change_program_modification_account(n: Linear<1, { MAX_MODIFIABLE_KEYS }>) {
        let program = vec![0u8];
        let program_hash = T::Hashing::hash(&program);
        let programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }])
        .unwrap();
        let derivation_path = vec![3u8];

        let sig_req_account: T::AccountId = whitelisted_caller();
        let balance =
            <T as pallet_staking_extension::Config>::Currency::minimum_balance() * 100u32.into();
        let _ = <T as pallet_staking_extension::Config>::Currency::make_free_balance_be(
            &sig_req_account,
            balance,
        );
        <ModifiableKeys<T>>::insert(
            sig_req_account.clone(),
            BoundedVec::try_from(vec![BoundedVec::default(); n as usize]).unwrap(),
        );
        <Registered<T>>::insert(
            &BoundedVec::default(),
            RegisteredInfo {
                program_modification_account: sig_req_account.clone(),
                programs_data: programs_info,
                derivation_path,
                version_number: T::KeyVersionNumber::get(),
            },
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(sig_req_account.clone()),
            BoundedVec::default(),
            sig_req_account.clone(),
        );

        assert_last_event::<T>(
            Event::ProgramModificationAccountChanged(
                sig_req_account.clone(),
                sig_req_account.clone(),
                BoundedVec::default(),
            )
            .into(),
        );
    }

    impl_benchmark_test_suite!(Registry, crate::mock::new_test_ext(), crate::mock::Test);
}
