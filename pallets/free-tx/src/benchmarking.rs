//! Benchmarking setup for pallet-free-tx
#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_support::{assert_ok, traits::EnsureOrigin};
use frame_system::RawOrigin;
use sp_std::prelude::Box;

use super::*;
#[allow(unused)]
use crate::Pallet as FreeTx;

benchmarks! {
  call_using_electricity {
    let caller: T::AccountId = whitelisted_caller();

    <TokenAccountData<T>>::insert(
      caller.clone(),
      TokenBalances {
          rechargable_tokens: 1,
          one_time_tokens_remaining: 0,
          tokens_used: RecentTokenUsage { latest_era: 0, count: 0 },
      },
  );

    let call: <T as Config>::Call = frame_system::Call::<T>::remark { remark: b"entropy rocks".to_vec() }.into();
  }: _(RawOrigin::Signed(caller.clone()), Box::new(call))
  verify {
    assert!(<TokenAccountData<T>>::get(caller).unwrap().tokens_used.count == 1);
  }
  set_individual_token_era_limit {
    let origin = T::UpdateOrigin::successful_origin();
    let free_tokens = 5 as TokenCount;
  }: {
    assert_ok!(
      <FreeTx<T>>::set_individual_token_era_limit(origin, free_tokens)
    );
  }
  verify {
    assert_eq!(MaxIndividualTokenUsagePerEra::<T>::get().unwrap(), free_tokens as TokenCount);
  }
  set_rechargable_token_balance {
    let origin = T::UpdateOrigin::successful_origin();
    let whitelisted_caller: T::AccountId = whitelisted_caller();
    let free_tokens = 5 as TokenCount;
  }: {
    assert_ok!(
      <FreeTx<T>>::set_rechargable_token_balance(origin, whitelisted_caller.clone(), free_tokens)
    );
  }
  verify {
    assert_eq!(TokenAccountData::<T>::get(whitelisted_caller).unwrap().rechargable_tokens, free_tokens as TokenCount);
  }
  give_one_time_use_tokens{
    let origin = T::UpdateOrigin::successful_origin();
    let whitelisted_caller: T::AccountId = whitelisted_caller();
    let free_tokens = 5 as TokenCount;
  }: {
    assert_ok!(
      <FreeTx<T>>::give_one_time_use_tokens(origin, whitelisted_caller.clone(), free_tokens)
    );
  }
  verify {
    assert_eq!(TokenAccountData::<T>::get(whitelisted_caller).unwrap().one_time_tokens_remaining, free_tokens as TokenCount);
  }
}
