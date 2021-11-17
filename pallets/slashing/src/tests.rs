use super::*;
use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};
use sp_runtime::Perbill;
use sp_staking::offence::Offence;

#[test]
fn slash_fraction_works() {
	new_test_ext().execute_with(|| {
		assert_eq!(TuxAngry::<()>::slash_fraction(1, 2), Perbill::from_perthousand(500));
	});
}


#[test]
fn offence_test() {
	new_test_ext().execute_with(|| {
		assert_ok!(Slashing::demo_offence(Origin::signed(1), vec![(1u64, 1u64)]));
	});
}
