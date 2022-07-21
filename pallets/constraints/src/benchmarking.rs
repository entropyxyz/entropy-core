//! Benchmarking setup for pallet-propgation

use super::*;

#[allow(unused)]
use crate::Pallet as Constraints;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_support::traits::Get;
use frame_system::{EventRecord, RawOrigin};

fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Pallet::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	// compare to the last event record
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

benchmarks! {

	add_whitelist_address {
		let a in 0 .. T::MaxWhitelist::get() - 1;
		let caller: T::AccountId = whitelisted_caller();

		let addresses = vec![vec![1u8]; a as usize];
		<AddressWhitelist<T>>::insert(caller.clone(), addresses.clone());


	}: _(RawOrigin::Signed(caller.clone()), vec![vec![2u8]])
	verify {
		assert_last_event::<T>(Event::AddressesWhitelisted(caller, vec![vec![2u8]]).into());
	}

}

impl_benchmark_test_suite!(Constraints, crate::mock::new_test_ext(), crate::mock::Test);
