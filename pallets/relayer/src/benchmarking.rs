//! Benchmarking setup for pallet-propgation

use codec::Encode;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_support::traits::{Get, OnInitialize};
use frame_system::{EventRecord, RawOrigin};
#[cfg(feature = "runtime-benchmarks")]
use pallet_constraints::benchmarking::generate_benchmarking_constraints;
use pallet_staking_extension::{
    benchmarking::create_validators, IsValidatorSynced, ServerInfo, SigningGroups, ThresholdServers,
};
use substrate_common::{Message, SigRequest, SIGNING_PARTY_SIZE as SIG_PARTIES};

use super::*;
#[allow(unused)]
use crate::Pallet as Relayer;

const SIG_HASH: &[u8; 64] = b"d188f0d99145e7ddbd0f1e46e7fd406db927441584571c623aff1d1652e14b06";

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

fn add_failures<T: Config>(failure_count: u32, block_number: T::BlockNumber) {
    let failures = vec![1u32; failure_count as usize];
    <Failures<T>>::insert(block_number, failures.clone());
}

fn add_messages<T: Config>(caller: T::AccountId, messages_count: u32) {
    for _ in 0..messages_count {
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let _ =
            <Relayer<T>>::prep_transaction(RawOrigin::Signed(caller.clone()).into(), sig_request);
    }
}

pub fn add_non_syncing_validators<T: Config>(
    sig_party_size: u32,
    syncing_validators: u32,
    sig_party_number: u8,
) {
    let validators = create_validators::<T>(sig_party_size, SEED);
    let account = account::<T::AccountId>("ts_account", 1, SEED);
    let server_info =
        ServerInfo { tss_account: account, x25519_public_key: NULL_ARR, endpoint: vec![20] };
    <SigningGroups<T>>::remove(sig_party_number);
    <SigningGroups<T>>::insert(sig_party_number, validators.clone());
    for c in 0..validators.len() {
        <ThresholdServers<T>>::insert(&validators[c], server_info.clone());
        if c >= syncing_validators.try_into().unwrap() {
            <IsValidatorSynced<T>>::insert(&validators[c], true);
        }
    }
    if syncing_validators == sig_party_size {
        <IsValidatorSynced<T>>::insert(&validators[0], true);
    }
}

benchmarks! {
  prep_transaction {
    let s in 0 .. MaxValidators::<T>::get() / SIG_PARTIES as u32;
    let account: T::AccountId = whitelisted_caller();
    let sig_party_size = MaxValidators::<T>::get() / SIG_PARTIES as u32;
    <Registered<T>>::insert(account.clone(), true);
    let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
    for i in 0..SIG_PARTIES {
        add_non_syncing_validators::<T>(sig_party_size, s, i as u8);
    }
  }: _(RawOrigin::Signed(account.clone()), sig_request.clone())
  verify {
    let ip_addresses = Pallet::<T>::get_ip_addresses().unwrap_or_default().0;
    assert_last_event::<T>(Event::<T>::SignatureRequested(Message {account: account.encode(), sig_request, ip_addresses}).into());
  }

  register {
    // number of addresses in the ACL
    let a in 0 .. <T as pallet_constraints::Config>::MaxAclLength::get();
    let b in 0 .. <T as pallet_constraints::Config>::MaxAclLength::get();
    let constraints = generate_benchmarking_constraints::<T>(a, b);

    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

  }:  _(RawOrigin::Signed(sig_req_account.clone()), constraint_account, Some(constraints))
  verify {
    assert_last_event::<T>(Event::SignalRegister(sig_req_account.clone()).into());
    assert!(Registering::<T>::contains_key(sig_req_account));
  }

  //TODO: Confirm done (for thor)

  move_active_to_pending_no_failure {
    let m in 0 .. 10;
    let caller: T::AccountId = whitelisted_caller();
    let block_number: T::BlockNumber = 10u32.into();
    let prune_block: T::BlockNumber = block_number.clone() - T::PruneBlock::get();
    let target_block: T::BlockNumber = block_number.clone() - 1u32.into();
    frame_system::Pallet::<T>::set_block_number(block_number);
    <Registered<T>>::insert(caller.clone(), true);

    frame_system::Pallet::<T>::set_block_number(target_block.clone());
    add_messages::<T>(caller.clone(), m.clone().into());
    assert_eq!(Messages::<T>::get(target_block.clone()).len() as u32, m.clone());
    <Responsibility<T>>::insert(target_block.clone(), caller.clone());
  }: {
    <Relayer<T>>::on_initialize(11u32.into());
  } verify {
    assert_eq!(Failures::<T>::get(block_number.clone()), None);
    assert_eq!(Pending::<T>::get(target_block.clone()).len() as u32, m.clone());
    assert_eq!(Messages::<T>::get(target_block).len() as u32, 0);
  }


  move_active_to_pending_failure {
    let m in 0 .. 10;
    let caller: T::AccountId = whitelisted_caller();
    let block_number: T::BlockNumber = 10u32.into();
    let prune_block: T::BlockNumber = block_number.clone() - T::PruneBlock::get();
    let target_block: T::BlockNumber = block_number.clone() - 1u32.into();
    frame_system::Pallet::<T>::set_block_number(block_number);
    <Registered<T>>::insert(caller.clone(), true);

    add_failures::<T>(1u32.into(), prune_block.clone());

    frame_system::Pallet::<T>::set_block_number(target_block.clone());
    add_messages::<T>(caller.clone(), m.clone().into());
    assert_eq!(Messages::<T>::get(target_block.clone()).len() as u32, m.clone());
    <Responsibility<T>>::insert(target_block.clone(), caller.clone());
  }: {
    <Relayer<T>>::on_initialize(11u32.into());
  } verify {
    assert_eq!(Failures::<T>::get(block_number.clone()), None);
    assert_eq!(Pending::<T>::get(target_block.clone()).len() as u32, m.clone());
    assert_eq!(Messages::<T>::get(target_block).len() as u32, 0);
  }

}

impl_benchmark_test_suite!(Relayer, crate::mock::new_test_ext(), crate::mock::Test);
