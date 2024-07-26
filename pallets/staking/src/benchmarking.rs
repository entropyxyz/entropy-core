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
use sp_std::{vec, vec::Vec};

use super::*;
#[allow(unused_imports)]
use crate::Pallet as Staking;

const NULL_ARR: [u8; 32] = [0; 32];
const SEED: u32 = 0;

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

    let server_info =
        ServerInfo { tss_account: threshold, x25519_public_key, endpoint: vec![20, 20] };

    if validate_also {
        assert_ok!(<Staking<T>>::validate(
            RawOrigin::Signed(bonder).into(),
            ValidatorPrefs::default(),
            server_info,
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

    let validator_preference = ValidatorPrefs::default();

    let server_info = ServerInfo {
        tss_account: threshold.clone(),
        x25519_public_key: NULL_ARR,
        endpoint: vec![20],
    };

  }:  _(RawOrigin::Signed(bonder.clone()), validator_preference, server_info)
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

  confirm_key_reshare_confirmed {
    let c in 0 .. SIGNING_PARTY_SIZE as u32;
    // leave a space for two as not to rotate and only confirm rotation
    let confirmation_num = c.checked_sub(2).unwrap_or(0);
    let signer_num =  SIGNING_PARTY_SIZE - 1;
    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    let second_signer: T::AccountId = account("second_signer", 0, SEED);
    let second_signer_id = <T as pallet_session::Config>::ValidatorId::try_from(second_signer.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    ThresholdToStash::<T>::insert(caller.clone(), validator_id_res.clone());

    // full signer list leaving room for one extra validator
    let mut signers = vec![second_signer_id.clone(); signer_num as usize];
    signers.push(validator_id_res.clone());
    Signers::<T>::put(signers.clone());

    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers,
      confirmations: vec![second_signer_id.clone(); confirmation_num as usize],
  });

  }: confirm_key_reshare(RawOrigin::Signed(caller.clone()))
  verify {
    assert_last_event::<T>(Event::<T>::SignerConfirmed(validator_id_res).into());
  }

  confirm_key_reshare_completed {
    // once less confirmation to always flip to rotate
    let confirmation_num = SIGNING_PARTY_SIZE - 1;

    let caller: T::AccountId = whitelisted_caller();
    let validator_id_res = <T as pallet_session::Config>::ValidatorId::try_from(caller.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    let second_signer: T::AccountId = account("second_signer", 0, SEED);
    let second_signer_id = <T as pallet_session::Config>::ValidatorId::try_from(second_signer.clone()).or(Err(Error::<T>::InvalidValidatorId)).unwrap();
    ThresholdToStash::<T>::insert(caller.clone(), validator_id_res.clone());
    // full signer list leaving room for one extra validator
    let mut signers = vec![second_signer_id.clone(); confirmation_num as usize];
    signers.push(validator_id_res.clone());

    Signers::<T>::put(signers.clone());
    NextSigners::<T>::put(NextSignerInfo {
      next_signers: signers.clone(),
      confirmations: vec![second_signer_id; confirmation_num as usize],
  });

  }:  confirm_key_reshare(RawOrigin::Signed(caller.clone()))
  verify {
    assert_last_event::<T>(Event::<T>::SignersRotation(signers.clone()).into());
  }
}

impl_benchmark_test_suite!(Staking, crate::mock::new_test_ext(), crate::mock::Test);
