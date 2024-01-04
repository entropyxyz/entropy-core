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
use frame_benchmarking::{
    account, benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller, Vec,
};
use frame_support::{
    assert_ok, ensure,
    sp_runtime::traits::StaticLookup,
    traits::{Currency, Get},
};
use frame_system::{EventRecord, RawOrigin};
use pallet_staking::{Pallet as FrameStaking, RewardDestination, ValidatorPrefs};

use super::*;
#[allow(unused_imports)]
use crate::Pallet as Staking;

const NULL_ARR: [u8; 32] = [0; 32];
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

fn prep_bond_and_validate<T: Config>(
    validate_also: bool,
    caller: T::AccountId,
    bonder: T::AccountId,
    threshold: T::AccountId,
    x25519_public_key: [u8; 32],
) {
    let reward_destination = RewardDestination::Account(caller.clone());
    let bond = <T as pallet_staking::Config>::Currency::minimum_balance() * 10u32.into();
    <T as Config>::Currency::make_free_balance_be(
        &bonder,
        <T as Config>::Currency::minimum_balance() * 10u32.into(),
    );
    assert_ok!(<FrameStaking<T>>::bond(
        RawOrigin::Signed(bonder.clone()).into(),
        bond,
        reward_destination,
    ));

    if validate_also {
        assert_ok!(<Staking<T>>::validate(
            RawOrigin::Signed(bonder).into(),
            ValidatorPrefs::default(),
            vec![20, 20],
            threshold,
            x25519_public_key
        ));
    }
}

benchmarks! {
  change_endpoint {
    let caller: T::AccountId = whitelisted_caller();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);
    let x25519_public_key = NULL_ARR;
    prep_bond_and_validate::<T>(true, caller.clone(), bonder.clone(), threshold, NULL_ARR);


  }:  _(RawOrigin::Signed(bonder.clone()), vec![30])
  verify {
    assert_last_event::<T>(Event::<T>::EndpointChanged(bonder, vec![30]).into());
  }

  change_threshold_accounts {
    let caller: T::AccountId = whitelisted_caller();
    let _bonder: T::AccountId = account("bond", 0, SEED);
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(_bonder.clone()).or(Err(Error::<T>::InvalidValidatorId));
    let bonder: T::ValidatorId = validator_id_res.expect("Issue converting account id into validator id");
    let threshold: T::AccountId = account("threshold", 0, SEED);
    let x25519_public_key: [u8; 32] = NULL_ARR;
    prep_bond_and_validate::<T>(true, caller.clone(), _bonder.clone(), threshold, NULL_ARR);


  }:  _(RawOrigin::Signed(_bonder.clone()), _bonder.clone(), NULL_ARR)
  verify {
    let server_info = ServerInfo {
      endpoint: vec![20, 20],
      tss_account: _bonder.clone(),
      x25519_public_key: NULL_ARR,
    };
    assert_last_event::<T>(Event::<T>::ThresholdAccountChanged(bonder, server_info).into());
  }


  withdraw_unbonded {
    let caller: T::AccountId = whitelisted_caller();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);

    prep_bond_and_validate::<T>(true, caller.clone(), bonder.clone(), threshold, NULL_ARR);
    let bond = <T as pallet_staking::Config>::Currency::minimum_balance() * 10u32.into();

    // assume fully unbonded as slightly more weight, but not enough to handle partial unbond
    assert_ok!(<FrameStaking<T>>::unbond(
      RawOrigin::Signed(bonder.clone()).into(),
      bond,
    ));


  }:  _(RawOrigin::Signed(bonder.clone()), 0u32)
  verify {
    // TODO: JA fix, pretty much benching this pathway requiers moving the session forward
    // This is diffcult, from the test we were able to mock it but benchamrks use runtime configs
    // It is fine for now but should come back to it
    // assert_last_event::<T>(Event::NodeInfoRemoved(caller).into());
  }

  validate {
    let caller: T::AccountId = whitelisted_caller();
    let bonder: T::AccountId = account("bond", 0, SEED);
    let threshold: T::AccountId = account("threshold", 0, SEED);
    let x25519_public_key: [u8; 32] = NULL_ARR;
    prep_bond_and_validate::<T>(false, caller.clone(), bonder.clone(), threshold.clone(), NULL_ARR);

    let validator_preferance = ValidatorPrefs::default();


  }:  _(RawOrigin::Signed(bonder.clone()), validator_preferance, vec![20], threshold.clone(), NULL_ARR)
  verify {
    assert_last_event::<T>(Event::<T>::NodeInfoChanged(bonder,  vec![20], threshold).into());
  }

  declare_synced {
    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    ThresholdToStash::<T>::insert(caller.clone(), validator_id_res.clone());

  }:  _(RawOrigin::Signed(caller.clone()), true)
  verify {
    assert_last_event::<T>(Event::<T>::ValidatorSyncStatus(validator_id_res,  true).into());
  }

  new_session_handler_helper {
    let c in 0 .. MaxValidators::<T>::get();
    let n in 0 .. MaxValidators::<T>::get();
    let current_validators = create_validators::<T>(c, SEED);
    let new_validators = create_validators::<T>(n, SEED_2);
    let _ =Staking::<T>::new_session_handler(&current_validators);

}: {
    let _ = Staking::<T>::new_session_handler(&new_validators);
} verify {
    let one_current_validator = &SigningGroups::<T>::get(0).unwrap();
    if n == 0 {
        if !one_current_validator.is_empty() {
            assert!(!new_validators.contains(&one_current_validator[0]));
        }
    } else {
        assert!(new_validators.contains(&one_current_validator[0]));
    }
}

}

impl_benchmark_test_suite!(Staking, crate::mock::new_test_ext(), crate::mock::Test);
