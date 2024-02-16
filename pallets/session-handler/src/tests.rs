// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::{mock::*, Error, ServerInfo, ThresholdToStash};
use frame_support::{assert_noop, assert_ok};
use pallet_session::SessionManager;

const NULL_ARR: [u8; 32] = [0; 32];

#[test]
fn tests_new_session_handler() {
    new_test_ext().execute_with(|| {
        let first_signing_group = || Staking::signing_groups(0).unwrap();
        let second_signing_group = || Staking::signing_groups(1).unwrap();

        // Setup a base of Validator 1 and 2 in two different signing groups
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(second_signing_group(), vec![2]);
        // If we set validators 1 and 2 in a new session, we expect them to be assigned to two
        // different signing groups
        assert_ok!(SessionHandler::new_session_handler(&[1, 2]));
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(second_signing_group(), vec![2]);

        // If we set validators 1 and 2 in a new session, in a different order as before, we expect
        // them to be assigned to the same signing group
        assert_ok!(SessionHandler::new_session_handler(&[2, 1]));
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(second_signing_group(), vec![2]);

        // If we have a session with a single validator, we expect to have an empty signing group
        assert_ok!(SessionHandler::new_session_handler(&[1]));
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(Staking::signing_groups(1), Some(vec![]));

        // If we have a session with more validators than signing groups, we expect that they will
        // be assigned across the different signing groups
        assert_ok!(SessionHandler::new_session_handler(&[1, 2, 3]));
        assert_eq!(first_signing_group(), vec![1, 2]);
        assert_eq!(second_signing_group(), vec![3]);

        // If we have a session with more validators than signing groups, we expect that they will
        // be assigned across the different signing groups
        assert_ok!(SessionHandler::new_session_handler(&[1, 2, 3, 4, 5]));
        assert_eq!(first_signing_group(), vec![1, 2, 4]);
        assert_eq!(second_signing_group(), vec![3, 5]);
    });
}
