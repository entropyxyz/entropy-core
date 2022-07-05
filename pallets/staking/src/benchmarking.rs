//! Benchmarking setup for pallet-propgation

use super::*;

#[allow(unused)]
use crate::Pallet as Staking;

use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_support::{assert_ok, traits::{Currency, Get, OnInitialize}, sp_runtime::traits::StaticLookup};
use frame_system::{EventRecord, Origin, RawOrigin};
use pallet_staking::Pallet as FrameStaking;
use pallet_staking::{RewardDestination, ValidatorPrefs};

fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Pallet::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	// compare to the last event record
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

fn prep_bond_and_validate<T: Config>(
	validate_also: bool,
	caller: T::AccountId,
	bonder: T::AccountId,
	threshold: T::AccountId,
) {
	let reward_destination = RewardDestination::Account(caller.clone());
	let bond = <T as pallet_staking::Config>::Currency::minimum_balance() * 10u32.into();
	<T as Config>::Currency::make_free_balance_be(&bonder.clone(), <T as Config>::Currency::minimum_balance() * 10u32.into());
	assert_ok!(<FrameStaking<T>>::bond(
		RawOrigin::Signed(bonder).into(),
		T::Lookup::unlookup(caller.clone()),
		bond,
		reward_destination,
	));

	if validate_also {
		assert_ok!(<Staking<T>>::validate(
			RawOrigin::Signed(caller.clone()).into(),
			ValidatorPrefs::default(),
			vec![20, 20],
			threshold,
		));
	}
}

const SEED: u32 = 0;

benchmarks! {
	change_endpoint {
		let caller: T::AccountId = whitelisted_caller();
		let bonder: T::AccountId = account("bond", 0, SEED);
		let threshold: T::AccountId = account("threshold", 0, SEED);

		prep_bond_and_validate::<T>(true, caller.clone(), bonder.clone(), threshold.clone());


	}:  _(RawOrigin::Signed(caller.clone()), vec![30])
	verify {
		assert_last_event::<T>(Event::EndpointChanged(caller, vec![30]).into());
	}


}

impl_benchmark_test_suite!(Staking, crate::mock::new_test_ext(), crate::mock::Test);
