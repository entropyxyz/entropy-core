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
#![allow(unused_imports)]
use entropy_shared::SIGNING_PARTY_SIZE;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_support::{
    assert_ok, ensure,
    sp_runtime::traits::StaticLookup,
    traits::{Currency, Get},
};
use frame_system::{EventRecord, RawOrigin};
use pallet_staking::{Pallet as FrameStaking, RewardDestination, ValidatorPrefs};
use pallet_staking_extension::SigningGroups;
use sp_std::{vec, vec::Vec};

use super::*;
#[allow(unused_imports)]
use crate::Pallet as SessionHandler;

const SEED: u32 = 0;
const SEED_2: u32 = 1;

type MaxValidators<T> =  <<T as pallet_staking::Config>::BenchmarkingConfig as pallet_staking::BenchmarkingConfig>::MaxValidators;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

pub fn create_validators<T: Config>(
    count: u32,
    seed: u32,
) -> Vec<<T as pallet_session::Config>::ValidatorId> {
    let candidates =
        (0..count).map(|c| account::<T::AccountId>("validator", c, seed)).collect::<Vec<_>>();
    let mut validators = vec![];
    for who in candidates {
        let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(who.clone())
            .or(Err(Error::<T>::InvalidValidatorId))
            .unwrap();
        validators.push(validator_id_res);
    }
    validators
}

benchmarks! {
  new_session_handler_helper {
    let c in 0 .. MaxValidators::<T>::get();
    let n in 0 .. MaxValidators::<T>::get();
    let current_validators = create_validators::<T>(c, SEED);
    let new_validators = create_validators::<T>(n, SEED_2);
    let _ = SessionHandler::<T>::new_session_handler(&current_validators);
    let mut current_subgroups: Vec<Vec<<T as pallet_session::Config>::ValidatorId>> = vec![];
    for signing_group in 0..SIGNING_PARTY_SIZE {
      let current_subgroup = SigningGroups::<T>::get(signing_group as u8).unwrap_or_default();
      current_subgroups.push(current_subgroup)
    };
}: {
    let _ = SessionHandler::<T>::new_session_handler(&new_validators);
} verify {
    let one_current_validator = &SigningGroups::<T>::get(0).unwrap_or_default();
    if n == 0 {
        if !one_current_validator.is_empty() {
            assert!(!new_validators.contains(&one_current_validator[0]));
        }
    } else {
      let mut new_subgroups: Vec<Vec<<T as pallet_session::Config>::ValidatorId>> = vec![];
      for signing_group in 0..SIGNING_PARTY_SIZE {
        let new_subgroup = SigningGroups::<T>::get(signing_group as u8).unwrap_or_default();
        new_subgroups.push(new_subgroup)
      };
        assert_last_event::<T>(Event::<T>::ValidatorSubgroupsRotated(current_subgroups,  new_subgroups).into());
        assert!(new_validators.contains(&one_current_validator[0]));
    }
}

}

impl_benchmark_test_suite!(SessionHandler, crate::mock::new_test_ext(), crate::mock::Test);
