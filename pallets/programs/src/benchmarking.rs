//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_support::traits::Currency;
use frame_system::{EventRecord, RawOrigin};
use sp_runtime::Saturating;

use super::*;
#[allow(unused)]
use crate::Pallet as ConstraintsPallet;

type CurrencyOf<T> = <T as Config>::Currency;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {

  update_program {
    let program = vec![10];
    let program_modification_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    let value = CurrencyOf::<T>::minimum_balance().saturating_mul(1_000_000_000u32.into());
    let _ = CurrencyOf::<T>::make_free_balance_be(&program_modification_account, value);

    <AllowedToModifyProgram<T>>::insert(program_modification_account.clone(), sig_req_account.clone(), ());
  }: _(RawOrigin::Signed(program_modification_account.clone()), sig_req_account, program.clone())
  verify {
    assert_last_event::<T>(
        Event::<T>::ProgramUpdated {
            program_modification_account,
            new_program: program
        }.into()
    );
  }
}

impl_benchmark_test_suite!(ConstraintsPallet, crate::mock::new_test_ext(), crate::mock::Test);
