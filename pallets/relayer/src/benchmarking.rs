//! Benchmarking setup for pallet-propgation

use codec::Encode;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_support::traits::{Get, OnInitialize};
use frame_system::{EventRecord, RawOrigin};
use substrate_common::{Constraints, Message, SigRequest};

use super::*;
#[allow(unused)]
use crate::Pallet as Relayer;

const SIG_HASH: &[u8; 64] = b"d188f0d99145e7ddbd0f1e46e7fd406db927441584571c623aff1d1652e14b06";

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

benchmarks! {
  prep_transaction {
    let account: T::AccountId = whitelisted_caller();

    <Registered<T>>::insert(account.clone(), true);
    let ip_addresses = Pallet::<T>::get_ip_addresses().unwrap();
    let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };

  }: _(RawOrigin::Signed(account.clone()), sig_request.clone())
  verify {
    assert_last_event::<T>(Event::<T>::SignatureRequested(Message {account: account.encode(), sig_request, ip_addresses}).into());
  }

  register {
    let sig_req_account: T::AccountId = whitelisted_caller();
    let constraint_account: T::AccountId = whitelisted_caller();

    let initial_constraints = Constraints::default();
  }:  _(RawOrigin::Signed(sig_req_account.clone()), constraint_account.clone(), Some(initial_constraints))
  verify {
    assert_last_event::<T>(Event::SignalRegister(sig_req_account.clone(), constraint_account).into());
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
