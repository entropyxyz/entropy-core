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
    let config_description = vec![11];
    let aux_description = vec![12];
    let mut hash_input: Vec<u8> = vec![];
    hash_input.extend(&program);
    hash_input.extend(&config_description);
    hash_input.extend(&aux_description);

    let program_hash = T::Hashing::hash(&hash_input);
    let deployer: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    let value = CurrencyOf::<T>::minimum_balance().saturating_mul(1_000_000_000u32.into());
    let _ = CurrencyOf::<T>::make_free_balance_be(&deployer, value);

  }: _(RawOrigin::Signed(deployer.clone()), program.clone(), config_description.clone(), aux_description.clone())
  verify {
    assert_last_event::<T>(
        Event::<T>::ProgramCreated {
            deployer,
            program_hash,
            config_description,
            aux_description
        }.into()
    );
  }

  remove_program {
    let p in 0..T::MaxOwnedPrograms::get();
    let program = vec![10];
    let config_description = vec![11];
    let aux_description = vec![12];
    let mut hash_input: Vec<u8> = vec![];
    hash_input.extend(&program);
    hash_input.extend(&config_description);
    hash_input.extend(&aux_description);

    let program_hash = T::Hashing::hash(&hash_input);
    let random_program = vec![11];
    let random_hash =  T::Hashing::hash(&random_program);
    let deployer: T::AccountId = whitelisted_caller();

    let value = CurrencyOf::<T>::minimum_balance().saturating_mul(1_000_000_000u32.into());
    let _ = CurrencyOf::<T>::make_free_balance_be(&deployer, value);
    <Programs<T>>::insert(program_hash.clone(), ProgramInfo {bytecode: program, config_description, aux_description, deployer: deployer.clone(), ref_counter: 0u128});
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
