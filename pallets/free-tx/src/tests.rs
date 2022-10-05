use frame_support::{assert_err, assert_ok};
use mock::{
    start_active_era, Call, Event as TestEvent, ExtBuilder, FreeTx, Origin, System, SystemCall,
    Test,
};
use sp_runtime::{DispatchError, ModuleError};

use super::*;

#[test]
fn call_using_electricity_works() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // enable free calls (1 free call per era)
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );

        // Dispatch a free call
        let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call));

        // Make sure the free call succeeded and event was emitted without an error
        System::assert_has_event(TestEvent::FreeTx(Event::ElectricitySpent(1, Ok(()))));
    });
}

#[test]
fn call_using_electricity_errors_when_child_call_errors() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // enable free calls (1 free call per era)
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        // this call will throw an error
        let call = Box::new(Call::System(SystemCall::kill_storage {
            keys: vec![b"this call will fail".to_vec()],
        }));
        let expected_error = DispatchError::BadOrigin;

        // Make sure call_using_electricity returns child call error to user
        assert_err!(FreeTx::call_using_electricity(Origin::signed(1), call), expected_error);

        // Make sure emitted event also contains the child error
        System::assert_has_event(TestEvent::FreeTx(Event::ElectricitySpent(
            1,
            Err(expected_error),
        )));
    });
}

#[test]
fn call_using_electricity_errors_when_no_coulombs_available() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // enable free calls (1 free call per era)
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        // user gets 1 free call by default, lets use it
        let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call));

        // Make sure the child call worked
        System::assert_last_event(TestEvent::FreeTx(Event::ElectricitySpent(1, Ok(()))));

        // try to do another free call when user has no free calls left
        let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));

        // make sure it fails bc no free calls left
        let expected_error = DispatchError::Module(ModuleError {
            index: 8,
            error: [1, 0, 0, 0],
            message: Some("NoCoulombsAvailable"),
        });
        assert_err!(FreeTx::call_using_electricity(Origin::signed(1), call), expected_error);
    });
}

#[test]
fn call_using_electricity_still_uses_electricity_on_child_fail() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // give one rechargable
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        // user gets 1 free call by default
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 1 as Coulombs);

        // choose a child call that will fail
        let call = Box::new(Call::System(SystemCall::kill_storage {
            keys: vec![b"this call will fail".to_vec()],
        }));

        // Make sure call_using_electricity fails only bc child fails, not because user has no free
        // calls left
        let expected_child_error = DispatchError::BadOrigin;
        assert_err!(FreeTx::call_using_electricity(Origin::signed(1), call), expected_child_error);

        // make sure free call was still consumed
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 0 as Coulombs);
    });
}

#[test]
fn batteries_refresh_every_era() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // enable electricity
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 5,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 5 as Coulombs);

        // make a call that works, check call is used
        let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call));
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 4 as Coulombs);

        // start a new era
        start_active_era(2);

        // make sure call count is refreshed
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 5 as Coulombs);
    });
}

#[test]
fn one_time_coulombs_are_consumed_and_not_recharged() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // give some coulombs
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 0,
                zaps: 5,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 5 as Coulombs);

        // make a call that works, check call is used
        let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call));
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 4 as Coulombs);

        // start a new era
        start_active_era(2);

        // make sure call count is refreshed
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 4 as Coulombs);
    });
}

#[test]
fn user_has_no_free_coulombs_by_default() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // make sure we have no free calls
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 0 as Coulombs);

        // make sure it fails bc coulombs are disabled
        let call =
            Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks2".to_vec() }));
        let expected_error = DispatchError::Module(ModuleError {
            index: 8,
            error: [1, 0, 0, 0],
            message: Some("NoCoulombsAvailable"),
        });
        assert_err!(FreeTx::call_using_electricity(Origin::signed(1), call), expected_error);
    });
}

// electricity limit works in middle of era
#[test]
fn set_individual_electricity_era_limit_works() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // give 5 batteries
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 0,
                zaps: 3,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 3 as Coulombs);

        // disable electricity
        FreeTx::set_individual_electricity_era_limit(Origin::signed(1), Some(0)).unwrap();

        // make sure call fails bc electricity is disabled
        let call =
            Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks2".to_vec() }));
        assert_err!(
            FreeTx::call_using_electricity(Origin::signed(1), call.clone()),
            DispatchError::Module(ModuleError {
                index: 8,
                error: [0, 0, 0, 0],
                message: Some("ElectricityIsDisabled"),
            })
        );

        // enable electricity usage at 2 coulombs per user
        FreeTx::set_individual_electricity_era_limit(Origin::signed(1), Some(2)).unwrap();
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 2 as Coulombs);

        // have user use two coulombs, then make sure they get an error
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call.clone()));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call.clone()));
        assert_err!(
            FreeTx::call_using_electricity(Origin::signed(1), call.clone()),
            DispatchError::Module(ModuleError {
                index: 8,
                error: [2, 0, 0, 0],
                message: Some("ElectricityEraLimitReached"),
            })
        );

        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 0 as Coulombs);

        // start a new era
        start_active_era(2);

        // cap is 2, but user shuold only have 1 zap left
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 1 as Coulombs);
    });
}

// one-time coulombs aren't touched until no more batteries are available
#[test]
fn zaps_arent_used_until_all_batteries_are_used() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // give some electricity
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 2,
                zaps: 5,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 7 as Coulombs);

        // use two coulombs
        let call =
            Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks2".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call.clone()));
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call.clone()));

        // make sure user hasn't used any zaps
        let mut expected_balance = ElectricalPanel {
            batteries: 2,
            zaps: 5,
            used: ElectricityMeter { latest_era: 1, count: 2 },
        };
        assert_eq!(ElectricalAccount::<Test>::get(1).unwrap(), expected_balance);

        // doing another call will though:
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call.clone()));
        expected_balance.zaps -= 1;
        expected_balance.used.count += 1;
        assert_eq!(ElectricalAccount::<Test>::get(1).unwrap(), expected_balance);
    });
}

// users with no coulombs get errors
#[test]
fn users_with_no_coulombs_get_errors() {
    ExtBuilder::default().build_and_execute(|| {
        let call =
            Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks2".to_vec() }));
        let no_coulombs_available_error = DispatchError::Module(ModuleError {
            index: 8,
            error: [1, 0, 0, 0],
            message: Some("NoCoulombsAvailable"),
        });

        // users by default have no electricity
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 0 as Coulombs);
        assert_err!(
            FreeTx::call_using_electricity(Origin::signed(1), call.clone()),
            no_coulombs_available_error
        );

        // give user one zap
        FreeTx::give_zaps(Origin::signed(1), 1, 1).unwrap();

        // make sure after a user uses all their coulombs, they get an error
        assert_eq!(FreeTx::coulombs_usable_this_era(&1u64), 1 as Coulombs);
        assert_ok!(FreeTx::call_using_electricity(Origin::signed(1), call.clone()));
        assert_err!(
            FreeTx::call_using_electricity(Origin::signed(1), call.clone()),
            no_coulombs_available_error
        );
    });
}
