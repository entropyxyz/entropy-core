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

//! Benchmarking setup for pallet-programs

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_support::{
    traits::{Currency, Get},
    BoundedVec,
};
use frame_system::{EventRecord, RawOrigin};
use sp_runtime::{traits::Hash, Saturating};
use sp_std::{vec, vec::Vec};

use super::*;
#[allow(unused)]
use crate::Pallet as ProgramsPallet;

type CurrencyOf<T> = <T as Config>::Currency;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {

  set_program {
    let program = vec![10];
    let configuration_schema = vec![11];
    let auxiliary_data_schema = vec![12];
    let oracle_data_pointers = BoundedVec::try_from([vec![13u8]].to_vec()).unwrap();
    let version_number = 0u8;
    let mut hash_input: Vec<u8> = vec![];
    hash_input.extend(&program);
    hash_input.extend(&configuration_schema);
    hash_input.extend(&auxiliary_data_schema);
    hash_input.extend(&vec![version_number]);
    let (_oracle_length, hash_input_with_oracle) =
    ProgramsPallet::<T>::get_length_and_hash_of_oracle(&oracle_data_pointers, hash_input).unwrap();

    let program_hash = T::Hashing::hash(&hash_input_with_oracle);
    let deployer: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    let value = CurrencyOf::<T>::minimum_balance().saturating_mul(1_000_000_000u32.into());
    let _ = CurrencyOf::<T>::make_free_balance_be(&deployer, value);

  }: _(
      RawOrigin::Signed(deployer.clone()),
      program.clone(),
      configuration_schema.clone(),
      auxiliary_data_schema.clone(),
      oracle_data_pointers.clone(),
      version_number
  )
  verify {
    assert_last_event::<T>(
        Event::<T>::ProgramCreated {
            deployer,
            program_hash,
            configuration_schema,
            auxiliary_data_schema,
            oracle_data_pointers,
            version_number
        }.into()
    );
  }

  remove_program {
    let p in 0..T::MaxOwnedPrograms::get();
    let program = vec![10];
    let configuration_schema = vec![11];
    let auxiliary_data_schema = vec![12];
    let oracle_data_pointers = BoundedVec::try_from([vec![13u8]].to_vec()).unwrap();
    let version_number = 0u8;
    let mut hash_input: Vec<u8> = vec![];
    hash_input.extend(&program);
    hash_input.extend(&configuration_schema);
    hash_input.extend(&auxiliary_data_schema);
    hash_input.extend(&vec![version_number]);
    let (_oracle_length, hash_input_with_oracle) =
    ProgramsPallet::<T>::get_length_and_hash_of_oracle(&oracle_data_pointers, hash_input).unwrap();

    let program_hash = T::Hashing::hash(&hash_input_with_oracle);
    let random_program = vec![11];
    let random_hash =  T::Hashing::hash(&random_program);
    let deployer: T::AccountId = whitelisted_caller();

    let value = CurrencyOf::<T>::minimum_balance().saturating_mul(1_000_000_000u32.into());
    let _ = CurrencyOf::<T>::make_free_balance_be(&deployer, value);
    <Programs<T>>::insert(program_hash.clone(), ProgramInfo {bytecode: program, configuration_schema, auxiliary_data_schema, oracle_data_pointers, deployer: deployer.clone(), ref_counter: 0u128, version_number});
    let mut program_hashes = vec![random_hash.clone(); p as usize];
    // remove one to make room for the targetted removal program hash
    program_hashes.pop();
    program_hashes.push(program_hash);

    let bounded_program_hashes: BoundedVec<T::Hash, T::MaxOwnedPrograms> = BoundedVec::try_from(program_hashes).unwrap();
    <OwnedPrograms<T>>::insert(deployer.clone(), bounded_program_hashes);
  }: _(RawOrigin::Signed(deployer.clone()), program_hash.clone())
  verify {
    assert_last_event::<T>(
        Event::<T>::ProgramRemoved {
            deployer,
            old_program_hash: program_hash
        }.into()
    );
  }
}

impl_benchmark_test_suite!(ProgramsPallet, crate::mock::new_test_ext(), crate::mock::Test);
