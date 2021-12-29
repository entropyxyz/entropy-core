use super::*;
use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};
use sp_runtime::Perbill;
use sp_staking::offence::Offence;

#[test]
fn slash_fraction_works() {
	new_test_ext().execute_with(|| {
		assert_eq!(TuxAngry::<()>::slash_fraction(1, 2), Perbill::from_perthousand(0));
	});
}

#[test]
fn offence_test() {
	new_test_ext().execute_with(|| {
		let exposure = pallet_staking::Exposure { total: 0, own: 0, others: vec![] };
		assert_ok!(Staking::force_new_era_always(Origin::root()));
		assert!(Session::validators().contains(&1));
		// slash would cause min validators to drop below min validators no offence
		assert_ok!(Slashing::demo_offence(
			Origin::signed(1),
			vec![(1u64, exposure.clone()), (2u64, exposure.clone())]
		));
		let mut offences = OFFENCES.with(|l| l.replace(vec![]));
		assert_eq!(offences.len(), 0);
		// causes offence
		assert_ok!(Slashing::demo_offence(Origin::signed(1), vec![(1u64, exposure)]));
		offences = OFFENCES.with(|l| l.replace(vec![]));
		assert_eq!(offences.len(), 1);
	});
}
