//! Benchmarking setup for pallet-free-tx
#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_staking::EraIndex;
use sp_std::prelude::Box;

use super::*;
#[allow(unused)] use crate::Pallet as FreeTx;

benchmarks! {
  try_free_call {
    let caller: T::AccountId = whitelisted_caller();
    FreeCallsRemaining::<T>::insert(&caller, FreeCallInfo { free_calls_remaining: 2 as FreeCallCount, era_index: 1 as EraIndex});

    let call: <T as Config>::Call = frame_system::Call::<T>::remark { remark: b"entropy rocks".to_vec() }.into();
  }: _(RawOrigin::Signed(caller.clone()), Box::new(call))
  verify {
    let FreeCallInfo { free_calls_remaining, .. } = FreeCallsRemaining::<T>::get(&caller).unwrap();
    assert_eq!(free_calls_remaining, 1 as FreeCallCount);
  }
  set_free_calls_per_era {
    let caller: T::AccountId = whitelisted_caller();
    let free_calls = 1 as FreeCallCount;
  }: _(RawOrigin::Root, free_calls as FreeCallCount)
  verify {
    assert_eq!(FreeCallsPerEra::<T>::get().unwrap(), free_calls as FreeCallCount);
  }
}
