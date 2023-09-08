//! Benchmarking setup for pallet-propgation
use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE as SIG_PARTIES};
use frame_benchmarking::{
    account, benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller, Vec,
};
use frame_support::traits::Get;
use frame_system::{EventRecord, RawOrigin};
#[cfg(feature = "runtime-benchmarks")]
use pallet_constraints::benchmarking::generate_benchmarking_constraints;
use pallet_staking_extension::{
    benchmarking::create_validators, IsValidatorSynced, ServerInfo, SigningGroups,
    ThresholdServers, ThresholdToStash,
};

use super::*;
#[allow(unused)]
use crate::Pallet as Relayer;

type MaxValidators<T> =  <<T as pallet_staking::Config>::BenchmarkingConfig as pallet_staking::BenchmarkingConfig>::MaxValidators;
const SEED: u32 = 0;
const NULL_ARR: [u8; 32] = [0; 32];

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

pub fn add_non_syncing_validators<T: Config>(
    sig_party_size: u32,
    syncing_validators: u32,
    sig_party_number: u8,
) -> Vec<<T as pallet_session::Config>::ValidatorId> {
    let validators = create_validators::<T>(sig_party_size, SEED);
    let account = account::<T::AccountId>("ts_account", 1, SEED);
    let server_info =
        ServerInfo { tss_account: account, x25519_public_key: NULL_ARR, endpoint: vec![20] };
    <SigningGroups<T>>::remove(sig_party_number);
    <SigningGroups<T>>::insert(sig_party_number, validators.clone());
    for (c, validator) in validators.iter().enumerate() {
        <ThresholdServers<T>>::insert(validator, server_info.clone());
        if c >= syncing_validators.try_into().unwrap() {
            <IsValidatorSynced<T>>::insert(validator, true);
        }
    }
    if syncing_validators == sig_party_size {
        <IsValidatorSynced<T>>::insert(&validators[0], true);
    }
    validators
}

benchmarks! {
  register {
    // number of addresses in the ACL
    let a in 0 .. <T as pallet_constraints::Config>::MaxAclLength::get();
    let b in 0 .. <T as pallet_constraints::Config>::MaxAclLength::get();
    let constraints = generate_benchmarking_constraints(a, b);

    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

  }:  _(RawOrigin::Signed(sig_req_account.clone()), constraint_account, KeyVisibility::Public, Some(constraints))
  verify {
    assert_last_event::<T>(Event::SignalRegister(sig_req_account.clone()).into());
    assert!(Registering::<T>::contains_key(sig_req_account));
  }

  confirm_register_registering {
    let c in 0 .. SIG_PARTIES as u32;
    let sig_req_account: T::AccountId = whitelisted_caller();
    let validator_account: T::AccountId = whitelisted_caller();
    let threshold_account: T::AccountId = whitelisted_caller();
    let sig_party_size = MaxValidators::<T>::get() / SIG_PARTIES as u32;
    for i in 0..SIG_PARTIES {
        let validators = add_non_syncing_validators::<T>(sig_party_size, 0, i as u8);
        <ThresholdToStash<T>>::insert(&threshold_account, &validators[i]);
    }
    <Registering<T>>::insert(&sig_req_account, RegisteringDetails::<T> {
        is_registering: true,
        constraint_account: sig_req_account.clone(),
        is_swapping: false,
        confirmations: vec![],
        constraints: None,
        key_visibility: KeyVisibility::Public,
        [0; 32],
    });
  }: confirm_register(RawOrigin::Signed(threshold_account), sig_req_account.clone(), 0)
  verify {
    assert_last_event::<T>(Event::<T>::AccountRegistering(sig_req_account, 0).into());
  }

confirm_register_registered {
    let c in 0 .. SIG_PARTIES as u32;
    let sig_req_account: T::AccountId = whitelisted_caller();
    let validator_account: T::AccountId = whitelisted_caller();
    let threshold_account: T::AccountId = whitelisted_caller();
    let sig_party_size = MaxValidators::<T>::get() / SIG_PARTIES as u32;
    for i in 0..SIG_PARTIES {
        let validators = add_non_syncing_validators::<T>(sig_party_size, 0, i as u8);
        <ThresholdToStash<T>>::insert(&threshold_account, &validators[i]);
    }
    let adjusted_sig_size = SIG_PARTIES - 1;
    let confirmation: Vec<u8> = (1u8..=adjusted_sig_size.try_into().unwrap()).collect();
    <Registering<T>>::insert(&sig_req_account, RegisteringDetails::<T> {
        is_registering: true,
        constraint_account: sig_req_account.clone(),
        is_swapping: false,
        confirmations: confirmation,
        constraints: None,
        key_visibility: KeyVisibility::Public,
        [0; 32],
    });
  }: confirm_register(RawOrigin::Signed(threshold_account), sig_req_account.clone(), 0)
  verify {
    assert_last_event::<T>(Event::<T>::AccountRegistered(sig_req_account).into());
  }

  confirm_register_swapping {
    let c in 0 .. SIG_PARTIES as u32;
    let sig_req_account: T::AccountId = whitelisted_caller();
    let validator_account: T::AccountId = whitelisted_caller();
    let threshold_account: T::AccountId = whitelisted_caller();
    let sig_party_size = MaxValidators::<T>::get() / SIG_PARTIES as u32;
    for i in 0..SIG_PARTIES {
        let validators = add_non_syncing_validators::<T>(sig_party_size, 0, i as u8);
        <ThresholdToStash<T>>::insert(&threshold_account, &validators[i]);
    }
    let adjusted_sig_size = SIG_PARTIES - 1;
    let confirmation: Vec<u8> = (1u8..=adjusted_sig_size.try_into().unwrap()).collect();
    <Registering<T>>::insert(&sig_req_account, RegisteringDetails::<T> {
        is_registering: true,
        constraint_account: sig_req_account.clone(),
        is_swapping: true,
        confirmations: confirmation,
        constraints: None,
        key_visibility: KeyVisibility::Public,
        [0; 32],
    });
  }: confirm_register(RawOrigin::Signed(threshold_account), sig_req_account.clone(), 0)
  verify {
    assert_last_event::<T>(Event::<T>::AccountRegistered(sig_req_account).into());
  }
}

impl_benchmark_test_suite!(Relayer, crate::mock::new_test_ext(), crate::mock::Test);
