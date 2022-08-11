//! Benchmarking setup for pallet-free-tx

use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_system::RawOrigin;

use super::*;
#[allow(unused)] use crate::Pallet as FreeTx;

benchmarks! {
  try_free_call {
    FreeCallsLeft::<T>::set(Some(2u8));

    // TODO: i just need a damn remark call
    let call = Box::new(<T as Config>::Call::System(frame_system::Call::<T>::remark { remark: b"entropy rocks".to_vec() }));
    let caller: T::AccountId = whitelisted_caller();
  }: _(RawOrigin::Signed(caller), call)
  verify {
    assert_eq!(FreeCallsLeft::<T>::get(), Some(1u8));
  }

  // we need to rerun this benchmark whenever we add additional free call sources
  check_free_call {
    FreeCallsLeft::<T>::set(Some(2u8));

    let caller: T::AccountId = whitelisted_caller();
  } : {
    <FreeTx<T>>::check_free_call(&caller)
  } verify {
    // make sure we don't hit saturating subtraction
    assert_eq!(FreeCallsLeft::<T>::get(), Some(1u8));
  }

  // we need to rerun this benchmark whenever we add additional free call sources
  process_free_call {
    FreeCallsLeft::<T>::set(Some(2u8));

    let caller: T::AccountId = whitelisted_caller();
  } : {
    <FreeTx<T>>::process_free_call(&caller);
  } verify {
    // make sure we don't hit saturating subtraction
    assert_eq!(FreeCallsLeft::<T>::get(), Some(1u8));
  }

  impl_benchmark_test_suite!(FreeTx, crate::mock::new_test_ext(), crate::mock::Test);
}
