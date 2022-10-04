//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_support::traits::{Get, OnInitialize};
use frame_system::{EventRecord, RawOrigin};
use substrate_common::SigRequest;

use super::*;
#[allow(unused)]
use crate::Pallet as Relayer;

fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::Event = generic_event.into();
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
        let sig_request = SigRequest { sig_id: 1u16, nonce: 1u32, signature: 1u32 };
        let _ =
            <Relayer<T>>::prep_transaction(RawOrigin::Signed(caller.clone()).into(), sig_request);
    }
}

benchmarks! {
  prep_transaction {
    let caller: T::AccountId = whitelisted_caller();
    <Registered<T>>::insert(caller.clone(), true);
    let sig_request = SigRequest { sig_id: 1u16, nonce: 1u32, signature: 1u32 };

  }: _(RawOrigin::Signed(caller.clone()), sig_request)
  verify {
    assert_last_event::<T>(Event::TransactionPropagated(caller).into());
  }

  register {
    let caller: T::AccountId = whitelisted_caller();

  }:  _(RawOrigin::Signed(caller.clone()))
  verify {
    assert_last_event::<T>(Event::SignalRegister(caller).into());
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
