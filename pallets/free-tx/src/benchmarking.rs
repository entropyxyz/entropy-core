//! Benchmarking setup for pallet-free-tx
#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_std::prelude::Box;

use super::*;
#[allow(unused)] use crate::Pallet as FreeTx;

benchmarks! {
  try_free_call {
    FreeCallsLeft::<T>::set(Some(2u8));

    let call: <T as Config>::Call = frame_system::Call::<T>::remark { remark: b"entropy rocks".to_vec() }.into();
    let caller: T::AccountId = whitelisted_caller();
  }: _(RawOrigin::Signed(caller), Box::new(call))
  verify {
    assert_eq!(FreeCallsLeft::<T>::get(), Some(1u8));
  }
}
